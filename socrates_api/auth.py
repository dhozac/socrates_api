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
import logging
from django.contrib.auth import get_backends
from rest_framework.authentication import BasicAuthentication

logger = logging.getLogger("socrates_api.auth")

class AuthzBasicAuthentication(BasicAuthentication):
    def authenticate(self, request):
        ret = super(AuthzBasicAuthentication, self).authenticate(request)
        if not isinstance(ret, tuple):
            return ret
        (user, instance) = ret
        on_behalf_of = request.META.get('HTTP_X_ON_BEHALF_OF', None)
        if user.is_superuser and on_behalf_of:
            logger.warning("%s made request to %s on behalf of %s", user.username, request.path, on_behalf_of)
            for backend in get_backends():
                if hasattr(backend, 'populate_user'):
                    return (backend.populate_user(on_behalf_of), None)
                else:
                    return (backend.get_user(on_behalf_of), None)

        return ret
