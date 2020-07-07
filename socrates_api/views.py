# Copyright 2015-2018 Klarna Bank AB
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#      http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.

from __future__ import absolute_import
from django.views.generic import DetailView
from django.http import Http404
from django.template import engines
from django.conf import settings
from rest_framework.views import APIView
from rest_framework.response import Response
from rest_framework import status
from rest_framework import generics
from rest_framework import permissions
from rest_framework.exceptions import PermissionDenied
from django_rethink import *
from socrates_api.tasks import *
from socrates_api.serializers import *
from celery import current_app
import logging
import time
import gevent
import hmac
import hashlib

logger = logging.getLogger("socrates_api")

class IsOwner(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.method == 'GET':
            return view.get_serializer(obj).has_read_permission(request.user)
        else:
            return view.get_serializer(obj).has_write_permission(request.user)

class HasQuotaPermission(permissions.BasePermission):
    def has_object_permission(self, request, view, obj):
        if request.user.is_superuser:
            return True
        user_groups = set(request.user.groups.all().values_list('name', flat=True))
        return obj['group'] in user_groups or obj['group'] == "_default_"

class IsAdminForUpdate(permissions.BasePermission):
    def has_permission(self, request, view):
        if request.method in ('POST', 'PUT', 'PATCH', 'DELETE'):
            return request.user.is_superuser
        else:
            return True

class NodeHMACPermission(permissions.BasePermission):
    """
    Responsible for ensuring that only key holders can invoke the node APIs.
    """
    def has_object_permission(self, request, view, obj):
        if request.user is not None and request.user.is_superuser:
            return True
        if 'hmac' not in request.query_params:
            logger.error("Request from %s is missing HMAC" % view.get_slug())
            return False
        h = hmac.HMAC(settings.SOCRATES_NODE_HMAC_KEY, (view.kwargs[view.slug_url_kwarg] + view.get_nonce()).encode("ascii"), hashlib.sha256)
        ours = h.hexdigest()
        if ours != request.query_params['hmac'].replace(":", ""):
            logger.error("Request from %s has invalid HMAC: %s != %s", view.get_slug(), ours, request.query_params['hmac'])
            return False
        return True

class NodeSlugMixin(object):
    slug_url_kwarg = "slug"
    def get_slug(self):
        """
        HPE includes whitespace padding in its service tags. Strip that.
        """
        slug = self.kwargs.get(self.slug_url_kwarg, None)
        if slug is not None:
            return slug.strip()
        else:
            return slug

class IPXERouterView(NodeSlugMixin, RethinkAPIMixin, APIView):
    serializer_class = AssetSerializer
    permission_classes = (NodeHMACPermission,)
    def get_object(self):
        try:
            obj = super(IPXERouterView, self).get_object()
            return obj
        except Http404:
            return {
                "version": 1,
                "state": "new",
                "service_tag": self.get_slug(),
                "asset_type": "server"
            }

    def get_nonce(self):
        return ""

    def get(self, request, slug=None, format=None):
        self.object = self.get_object()
        if self.object.get('maintenance', False):
            name = "intake"
        elif self.object.get('provisioning', False) and self.object['state'] == 'ready' and (self.object['asset_type'] != "server" or 'by_id' in self.object['provision']['storage']['os']):
            name = self.object['provision']['os']
        else:
            name = "intake"
        os = OperatingSystemSerializer.get(name=name)
        template = engines['django'].from_string(os['ipxe_script'])
        context = {'object': self.object, 'request': request}
        if 'provision' in context['object']:
            context['network'] = NetworkSerializer.get_by_asset_vlan(context['object'], context['object']['provision']['vlan'])
            ipam = get_ipam(context['object'], False)
            context['network']['ipam'] = ipam.ip_prefix_get(context['network'])
            context['networks'] = []
            for vlan in context['object']['provision'].get('vlans', []):
                network = NetworkSerializer.get_by_asset_vlan(context['object'], vlan)
                network['ipam'] = ipam.ip_prefix_get(network)
                context['networks'].append({'vlan': vlan, 'network': network})
        return HttpResponse(template.render(context), content_type="text/plain")

class IntakeReportView(NodeSlugMixin, RethinkAPIMixin, APIView):
    table_name = 'assets_raw'
    serializer_class = AssetSerializer
    permission_classes = (NodeHMACPermission,)

    def get_nonce(self):
        nonce = self.request.query_params.get('nonce', '1')
        slug = self.get_slug()
        try:
            asset = AssetSerializer.get(service_tag=slug)
        except RethinkObjectNotFound:
            asset = {'version': 1}
        if int(nonce) > asset['version'] or asset['version'] - int(nonce) > 7:
            logger.error("Nonce %s is too low for asset %s version %d", nonce, slug, asset['version'])
            raise PermissionDenied()
        return nonce

    def post(self, request, format=None, slug=None):
        slug = self.get_slug()
        try:
            self.object = self.get_object()
        except Http404:
            # Assets are created by this.
            pass
        data = request.data
        if data['returncode'] != 0:
            logger.error("Intake step %s failed on %s", data['step'], slug)
        if 'data' not in data or data['data'] is None:
            data['data'] = {}
        data['data']['timestamp'] = time.time()
        if 'failed' not in data['data'] and 'success' in data['data']:
            data['data']['failed'] = not data['data']['success']
        elif 'success' not in data['data'] and 'failed' in data['data']:
            data['data']['success'] = not data['data']['failed']
        elif 'success' not in data['data'] and 'failed' not in data['data']:
            data['data']['failed'] = True
            data['data']['success'] = False
        update = {data['step']: data['data']}
        if max(r.table(self.table_name).get_all(slug, index="service_tag").update(r.expr(update, nesting_depth=40)).run(self.get_connection()).values()) == 0:
            # Unable to find an entry to update, create one.
            update['service_tag'] = slug
            r.table(self.table_name).insert(update).run(self.get_connection())
        extract_asset_from_raw.apply_async((slug, data['step'] in ('reboot', 'poweroff')))
        return Response({'success': True})

class IntakeConfigView(NodeSlugMixin, APIView):
    def get(self, request, format=None, slug=None):
        try:
            asset = AssetSerializer.get(service_tag=self.get_slug())
        except RethinkObjectNotFound:
            asset = {}
        return Response({
            'hyperthreading': asset.get('provision', {}).get('hyperthreading', False),
            'storage': asset.get('provision', {}).get('storage', {}),
        })

class KickstartView(RethinkSingleObjectMixin, DetailView):
    table_name = 'assets'
    slug_field = 'service_tag'
    def get_template_names(self):
        conn = self.get_connection()
        obj = next(r.table('os').get_all(self.object['provision']['os'], index='name').run(conn))
        return engines['django'].from_string(obj['kickstart'])
    def get_context_data(self, **kwargs):
        context = super(KickstartView, self).get_context_data(**kwargs)
        context['network'] = NetworkSerializer.get_by_asset_vlan(context['object'], context['object']['provision']['vlan'])
        ipam = get_ipam(context['object'], False)
        context['network']['ipam'] = ipam.ip_prefix_get(context['network'])
        context['networks'] = []
        for vlan in context['object']['provision'].get('vlans', []):
            network = NetworkSerializer.get_by_asset_vlan(context['object'], vlan)
            network['ipam'] = ipam.ip_prefix_get(network)
            context['networks'].append({'vlan': vlan, 'network': network})
        return context

class KickstartCompleteView(APIView):
    def get(self, request, format=None, slug=None):
        service_tag = slug
        task = asset_get.s(service_tag) | \
               asset_update.s({'state': 'in-use', 'provisioning': False, 'log': 'Kickstart complete'}) | \
               reconfigure_network_port.s() | \
               ipmi_reboot.s() | \
               run_playbook.s('defaults.yml') | \
               event_emit.s('provisioned')
        task.apply_async(countdown=60)
        return Response(True)

class WarrantyLookupBatchView(APIView):
    def get(self, request, format=None, slug=None):
        task = batch_update_warranties_from_vendors.s()
        task.apply_async()
        return Response(True)

class WarrantyLookupView(APIView):
    permission_classes = (permissions.IsAuthenticated, IsOwner)
    def get(self, request, format=None, slug=None):
        service_tag = slug
        task = asset_get.s(service_tag) | \
               update_warranty_from_vendor.s()
        return Response(task.apply().result)

class WarrantySendReportView(APIView):
    def post(self, request, format=None, slug=None):
        if 'days' not in request.data:
            return Response({'detail': "Required argument 'end_date' is missing"}, status=status.HTTP_400_BAD_REQUEST)
        elif 'recipients' not in request.data:
            return Response({'detail': "Required argument 'recipients' is missing"}, status=status.HTTP_400_BAD_REQUEST)
        elif 'max_age' not in request.data:
            return Response({'detail': "Required argument 'max_age' is missing"}, status=status.HTTP_400_BAD_REQUEST)
        days = int(request.data['days'])
        max_age = int(request.data['max_age'])
        recipients = request.data['recipients']
        results = {}
        task = send_expiring_warranty_report.s(recipients, days)
        results['expiring_warranties'] = task.apply().result
        task = send_eol_report.s(request.data['recipients'], max_age, days)
        results['eol_assets'] = task.apply().result
        task = send_no_warranty_report.s(request.data['recipients'])
        results['no_warranty_assets'] = task.apply().result
        return Response(results)

class AssetListCreateView(RethinkAPIMixin, generics.ListCreateAPIView):
    table_name = 'assets'
    slug_field = 'service_tag'
    group_filter_fields = ['owner', 'managers']
    serializer_class = AssetSerializer
    permission_classes = (permissions.IsAuthenticated, IsOwner)

    def default_filter_queryset(self, queryset):
        if 'state' not in self.request.query_params:
            queryset = queryset.filter(lambda obj: obj['state'] != 'deleted')
        if 'grandparents' in self.request.query_params:
            queryset = queryset.merge(lambda asset:
                    r.branch(asset.has_fields('parent'),
                        {'grandparents': [asset['parent']]},
                        {}
                    )
                ) \
                .merge(lambda asset:
                    r.branch(asset.has_fields('grandparents'),
                        {'grandparents': asset['grandparents'] + [r.table("assets").get_all(asset['grandparents'][-1], index="service_tag").nth(0)['parent'].default(None)]},
                        {}
                    )
                ) \
                .merge(lambda asset:
                    r.branch(asset.has_fields('grandparents'),
                        {'grandparents': asset['grandparents'] + [r.table("assets").get_all(asset['grandparents'][-1], index="service_tag").nth(0)['parent'].default(None)]},
                        {}
                    )
                ) \
                .filter(lambda asset:
                    r.expr(self.request.query_params.get('grandparents')) \
                    .set_intersection(asset['grandparents']).count() > 0)
        return queryset

class AssetDetailView(RethinkAPIMixin, generics.RetrieveUpdateDestroyAPIView):
    table_name = 'assets'
    slug_field = 'service_tag'
    serializer_class = AssetSerializer
    permission_classes = (permissions.IsAuthenticated, IsOwner)

class AssetHistoryListView(ObjectHistoryListView):
    def get_serializer_and_id(self):
        if 'id' in self.kwargs:
            return (AssetSerializer, self.kwargs['id'])
        elif 'slug' in self.kwargs:
            asset = AssetSerializer.get(service_tag=self.kwargs['slug'])
            return (AssetSerializer, asset['id'])
        else:
            raise NotFound()
    def get_queryset(self):
        queryset = super(AssetHistoryListView, self).get_queryset()
        if not self.request.user.is_superuser:
            queryset = queryset.without({"object": {"oob": True}})
        return queryset

class AssetIPMIActionView(RethinkAPIMixin, APIView):
    table_name = 'assets'
    slug_field = 'service_tag'
    serializer_class = AssetSerializer
    permission_classes = (permissions.IsAuthenticated, IsOwner)
    ACTIONS = {
        'reboot': ipmi_reboot.s(),
        'shutdown': ipmi_shutdown.s(),
        'poweron': ipmi_poweron.s(),
        'reboot_pxe': ipmi_boot_pxe.s() | ipmi_reboot.s(),
    }
    def post(self, request, format=None, slug=None, id=None):
        if 'action' not in request.data:
            return Response({'detail': "Required argument 'action' is missing"}, status=status.HTTP_400_BAD_REQUEST)
        elif 'log' not in request.data:
            return Response({'detail': "Required argument 'log' is missing"}, status=status.HTTP_400_BAD_REQUEST)
        elif request.data['action'] not in self.ACTIONS:
            return Response({'detail': "'action' has unknown value '%s', supported are: %s" % (request.data['action'], ", ".join(self.ACTIONS.keys()))}, status=status.HTTP_400_BAD_REQUEST)
        if slug is not None:
            task = asset_get.s(slug)
        elif id is not None:
            task = asset_get_by_id.s(id)
        task = task | asset_update.s({'latest_action': request.data['action'], 'log': request.data['log']}, context={'username': request.user.username}) | self.ACTIONS[request.data['action']]
        result = task.apply_async()
        if 'sync' in request.data and request.data['sync']:
            result.get()
            return Response({'detail': 'Action completed', 'sync': True})
        else:
            return Response({'detail': 'Action scheduled', 'sync': False})
    def get(self, request, format=None, slug=None, id=None):
        if slug is not None:
            task = asset_get.s(slug)
        elif id is not None:
            task = asset_get_by_id.s(id)
        task = task | ipmi_power_state.s()
        try:
            result = task.apply_async(expires=settings.SOCRATES_CHANGEFEED_MAX_WAIT).get(propagate=True)
            if result is None:
                raise Exception("Unable to determine power-state")
            return Response({'power_state': result})
        except:
            return Response({}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class OSListCreateView(RethinkAPIMixin, generics.ListCreateAPIView):
    table_name = 'os'
    slug_field = 'name'
    serializer_class = OperatingSystemSerializer
    permission_classes = (permissions.IsAuthenticated, IsAdminForUpdate)

class OSDetailView(RethinkAPIMixin, generics.RetrieveUpdateDestroyAPIView):
    table_name = 'os'
    slug_field = 'name'
    serializer_class = OperatingSystemSerializer
    permission_classes = (permissions.IsAdminUser,)

class HealthCheckView(RethinkAPIMixin, APIView):
    def get(self, request, format=None):
        result = list(r.db("rethinkdb").table("current_issues").run(self.get_connection()))
        if len([issue for issue in result if issue['critical']]) > 0:
            return Response(False, status=status.HTTP_503_SERVICE_UNAVAILABLE)
        return Response(True)

class NetworkListCreateView(RethinkAPIMixin, generics.ListCreateAPIView):
    group_filter_fields = ['permissions_read', 'permissions_create', 'permissions_write']
    serializer_class = NetworkSerializer
    permission_classes = (permissions.IsAuthenticated, IsAdminForUpdate, RethinkSerializerPermission)

class NetworkDetailView(RethinkAPIMixin, generics.RetrieveUpdateDestroyAPIView):
    group_filter_fields = ['permissions_read', 'permissions_create', 'permissions_write']
    serializer_class = NetworkSerializer
    permission_classes = (permissions.IsAuthenticated, RethinkSerializerPermission)

    def get_slug(self):
        if not all([i in self.kwargs for i in ['vrf', 'network', 'length']]):
            return None
        return [int(self.kwargs['vrf']), self.kwargs['network'], int(self.kwargs['length'])]

class QuotaListCreateView(RethinkAPIMixin, generics.ListCreateAPIView):
    table_name = 'quotas'
    pk_field = 'id'
    group_filter_fields = ['group']
    group_filter_extras = ['_default_']
    serializer_class = QuotaSerializer
    permission_classes = (permissions.IsAuthenticated, IsAdminForUpdate, HasQuotaPermission)

class QuotaDetailView(RethinkAPIMixin, generics.RetrieveUpdateDestroyAPIView):
    table_name = 'quotas'
    pk_field = 'id'
    slug_field = 'group'
    serializer_class = QuotaSerializer
    permission_classes = (permissions.IsAuthenticated, IsAdminForUpdate, HasQuotaPermission)

class EventFeedView(RethinkAPIMixin, APIView):
    table_name = 'events'
    serializer_class = EventSerializer
    permission_classes = (permissions.IsAuthenticated,)
    def _filter_queryset(self, queryset):
        return queryset
    def get(self, request, format=None, id=None, slug=None):
        queryset = self.get_queryset()
        conn = self.get_connection()
        if 'id' in request.query_params:
            seen_id = request.query_params['id']
            try:
                old_timestamp = queryset.get(seen_id).run(conn)['timestamp']
            except:
                return Response({'id': 'invalid event id'}, status=status.HTTP_400_BAD_REQUEST)
            queryset = queryset.filter(lambda row: (row['timestamp'] >= old_timestamp) & (row['id'] != seen_id))
        if id is not None:
            queryset = queryset.filter({'asset_id': id})
        elif slug is not None:
            queryset = queryset.filter({'service_tag': slug})
        results = list(queryset.order_by("timestamp").run(conn))
        if len(results) == 0:
            feed = queryset.changes().filter({'old_val': None}).run(conn)
            try:
                results = [gevent.with_timeout(settings.SOCRATES_CHANGEFEED_MAX_WAIT, feed.next)['new_val']]
            except gevent.Timeout:
                return Response(status=status.HTTP_204_NO_CONTENT)
        response = Response(results)
        return response

class CeleryTaskResultListView(RethinkAPIMixin, generics.ListAPIView):
    table_name = 'celery_taskmeta'
    pk_field = 'id'
    serializer_class = CeleryTaskResultSerializer
    permission_classes = (permissions.IsAuthenticated, permissions.IsAdminUser)
    def default_filter_queryset(self, queryset):
        return queryset. \
            merge(lambda result: {"task": r.table("celery_taskqueue").get_all(result['id'], index="result_id").nth(0).default({})})

class CeleryTaskResultDetailView(RethinkAPIMixin, generics.RetrieveUpdateAPIView):
    table_name = 'celery_taskmeta'
    pk_field = 'id'
    serializer_class = CeleryTaskResultSerializer
    permission_classes = (permissions.IsAuthenticated, permissions.IsAdminUser)

class CeleryTaskQueueDetailView(RethinkAPIMixin, generics.RetrieveUpdateAPIView):
    table_name = 'celery_taskqueue'
    pk_index_name = 'result_id'
    serializer_class = CeleryTaskQueueSerializer
    permission_classes = (permissions.IsAuthenticated, permissions.IsAdminUser)

class TaskInvokeView(RethinkAPIMixin, APIView):
    permission_classes = (permissions.IsAuthenticated, permissions.IsAdminUser)
    def post(self, request, format=None, slug=None):
        if slug not in current_app.tasks:
            return Response(status=status.HTTP_404_FILE_NOT_FOUND)
        args = request.data.get("args", [])
        kwargs = request.data.get("kwargs", {})
        logger.info("%s invoked %s(%r, %r)" % (request.user.username, slug, args, kwargs))
        current_app.tasks[slug].apply_async(args=args, kwargs=kwargs)
        return Response(status=status.HTTP_204_NO_CONTENT)

class UserInfoView(APIView):
    permission_classes = (permissions.IsAuthenticated,)
    def get(self, request, format=None):
        return Response({
            "username": request.user.username,
            "logged_in": request.user.is_authenticated if isinstance(request.user.is_authenticated, bool) else request.user.is_authenticated(),
            "is_superuser": request.user.is_superuser,
            "is_console_user": request.user.is_console_user,
        })

class LoadBalancerListCreateView(RethinkAPIMixin, generics.ListCreateAPIView):
    group_filter_fields = ['permissions_read', 'permissions_create', 'permissions_write']
    serializer_class = LoadBalancerSerializer
    permission_classes = (permissions.IsAuthenticated, RethinkSerializerPermission)

class LoadBalancerDetailView(RethinkAPIMixin, generics.RetrieveUpdateDestroyAPIView):
    group_filter_fields = ['permissions_read', 'permissions_create', 'permissions_write']
    serializer_class = LoadBalancerSerializer
    permission_classes = (permissions.IsAuthenticated, RethinkSerializerPermission)

class LoadBalancerIRuleListCreateView(RethinkAPIMixin, generics.ListCreateAPIView):
    group_filter_fields = ['permissions_read', 'permissions_create', 'permissions_write']
    serializer_class = LoadBalancerIRuleSerializer
    permission_classes = (permissions.IsAuthenticated, RethinkSerializerPermission)

class LoadBalancerIRuleDetailView(RethinkAPIMixin, generics.RetrieveUpdateDestroyAPIView):
    group_filter_fields = ['permissions_read', 'permissions_create', 'permissions_write']
    serializer_class = LoadBalancerIRuleSerializer
    permission_classes = (permissions.IsAuthenticated, RethinkSerializerPermission)

class FirewallAddressGroupListCreateView(RethinkAPIMixin, generics.ListCreateAPIView):
    group_filter_fields = ['permissions_read', 'permissions_create', 'permissions_write']
    serializer_class = FirewallAddressGroupSerializer
    permission_classes = (permissions.IsAuthenticated, RethinkSerializerPermission)

class FirewallAddressGroupDetailView(RethinkAPIMixin, generics.RetrieveUpdateDestroyAPIView):
    group_filter_fields = ['permissions_read', 'permissions_create', 'permissions_write']
    serializer_class = FirewallAddressGroupSerializer
    permission_classes = (permissions.IsAuthenticated, RethinkSerializerPermission)

class FirewallRuleSetListCreateView(RethinkAPIMixin, generics.ListCreateAPIView):
    group_filter_fields = ['permissions_read', 'permissions_create', 'permissions_write']
    public_field = 'public'
    serializer_class = FirewallRuleSetSerializer
    permission_classes = (permissions.IsAuthenticated, RethinkSerializerPermission)

class FirewallRuleSetDetailView(RethinkAPIMixin, generics.RetrieveUpdateDestroyAPIView):
    group_filter_fields = ['permissions_read', 'permissions_create', 'permissions_write']
    public_field = 'public'
    serializer_class = FirewallRuleSetSerializer
    permission_classes = (permissions.IsAuthenticated, RethinkSerializerPermission)
