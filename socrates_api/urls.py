"""socrates URL Configuration

The `urlpatterns` list routes URLs to views. For more information please see:
    https://docs.djangoproject.com/en/1.8/topics/http/urls/
Examples:
Function views
    1. Add an import:  from my_app import views
    2. Add a URL to urlpatterns:  url(r'^$', views.home, name='home')
Class-based views
    1. Add an import:  from other_app.views import Home
    2. Add a URL to urlpatterns:  url(r'^$', Home.as_view(), name='home')
Including another URLconf
    1. Add an import:  from blog import urls as blog_urls
    2. Add a URL to urlpatterns:  url(r'^blog/', include(blog_urls))
"""
from __future__ import absolute_import
from django.conf.urls import include, url
from socrates_api.views import *
from django.views.generic.base import RedirectView

app_name = 'socrates_api'
urlpatterns = [
    url(r'^boot/(?P<slug>[A-Za-z0-9 -]+)$', IPXERouterView.as_view(), name='ipxe_router'),
    url(r'^config/(?P<slug>[A-Za-z0-9 -]+)$', IntakeConfigView.as_view(), name='intake_config'),
    url(r'^intake/(?P<slug>[A-Za-z0-9 -]+)$', IntakeReportView.as_view(), name='intake_report'),
    url(r'^tkickstart/(?P<slug>[A-Za-z0-9 -]+)$', KickstartView.as_view(), name='kickstart'),
    url(r'^tkickstartcomplete/(?P<slug>[A-Za-z0-9 -]+)$', KickstartCompleteView.as_view(), name='kickstart_complete'),
    url(r'^asset/(?P<id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/?$', AssetDetailView.as_view(), name='asset_detail_id'),
    url(r'^asset/(?P<id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/history/?$', AssetHistoryListView.as_view(), name='asset_history_list_id'),
    url(r'^asset/(?P<id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})/ipmi/?$', AssetIPMIActionView.as_view(), name='asset_ipmi_action_id'),
    url(r'^asset/(?P<slug>[A-Za-z0-9 -]+)/ipmi/$', AssetIPMIActionView.as_view(), name='asset_ipmi_action'),
    url(r'^asset/(?P<slug>[A-Za-z0-9 -]+)/?$', AssetDetailView.as_view(), name='asset_detail'),
    url(r'^asset/(?P<slug>[A-Za-z0-9 -]+)/history/?$', AssetHistoryListView.as_view(), name='asset_history_list'),
    url(r'^asset/$', AssetListCreateView.as_view(), name='asset_list'),
    url(r'^os/(?P<slug>[A-Za-z0-9-.]+)', OSDetailView.as_view(), name='os_detail'),
    url(r'^os/', OSListCreateView.as_view(), name='os_list'),
    url(r'^network/(?P<id>[A-Za-z0-9-]+)$', NetworkDetailView.as_view(), name='network_detail_id'),
    url(r'^network/(?P<vrf>[0-9]+)/(?P<network>[0-9a-f.:]+)/(?P<length>[0-9]+)/?$', NetworkDetailView.as_view(), name='network_detail'),
    url(r'^network/', NetworkListCreateView.as_view(), name='network_list'),
    url(r'^quota/(?P<id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})$', QuotaDetailView.as_view(), name='quota_detail_id'),
    url(r'^quota/(?P<slug>[A-Za-z0-9-._]+)$', QuotaDetailView.as_view(), name='quota_detail'),
    url(r'^quota/', QuotaListCreateView.as_view(), name='quota_list'),
    url(r'^event/feed/((?P<id>[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12})|(?P<slug>[A-Za-z0-9 -]+))?/?$', EventFeedView.as_view(), name='event_feed'),
    url(r'^task/result/(?P<id>[A-Za-z0-9-]+)$', CeleryTaskResultDetailView.as_view(), name='celery_task_result_detail'),
    url(r'^task/result/$', CeleryTaskResultListView.as_view(), name='celery_task_result_list'),
    url(r'^task/queue/(?P<id>[A-Za-z0-9-]+)$', CeleryTaskQueueDetailView.as_view(), name='celery_task_queue_detail'),
    url(r'^task/invoke/(?P<slug>.*)/?$', TaskInvokeView.as_view(), name='task_invoke'),
    url(r'^health/', HealthCheckView.as_view(), name='health_check'),
    url(r'^warrantylookup/batch/', WarrantyLookupBatchView.as_view(), name='warranty_lookup_batch'),
    url(r'^warrantylookup/sendreport/$', WarrantySendReportView.as_view(), name='warranty_send_report'),
    url(r'^warrantylookup/(?P<slug>[A-Za-z0-9 -]+)/?$', WarrantyLookupView.as_view(), name='warranty_lookup'),
    url(r'^user/me/?$', UserInfoView.as_view(), name='user_info'),
    url(r'^loadbalancerirule/(?P<slug>[A-Za-z0-9-._]+)/?$', LoadBalancerIRuleDetailView.as_view(), name='loadbalancer_irule_detail'),
    url(r'^loadbalancerirule/', LoadBalancerIRuleListCreateView.as_view(), name='loadbalancer_irule_list'),
    url(r'^loadbalancer/(?P<slug>[A-Za-z0-9-._]+)/?$', LoadBalancerDetailView.as_view(), name='loadbalancer_detail'),
    url(r'^loadbalancer/', LoadBalancerListCreateView.as_view(), name='loadbalancer_list'),
    url(r'^firewall/addressgroup/(?P<slug>[A-Za-z0-9-._]+)$', FirewallAddressGroupDetailView.as_view(), name='firewall_addressgroup_detail'),
    url(r'^firewall/addressgroup/', FirewallAddressGroupListCreateView.as_view(), name='firewall_addressgroup_list'),
    url(r'^firewall/ruleset/(?P<slug>[A-Za-z0-9-._]+)$', FirewallRuleSetDetailView.as_view(), name='firewall_ruleset_detail'),
    url(r'^firewall/ruleset/', FirewallRuleSetListCreateView.as_view(), name='firewall_ruleset_list'),
]
