..
..
.. Licensed under the Apache License, Version 2.0 (the "License");
.. you may not use this file except in compliance with the License.
.. You may obtain a copy of the License at
..
..     http://www.apache.org/licenses/LICENSE-2.0
..
.. Unless required by applicable law or agreed to in writing, software
.. distributed under the License is distributed on an "AS IS" BASIS,
.. WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
.. See the License for the specific language governing permissions and
.. limitations under the License.
..

.. _to-letsencrypt-dnsrecord:

*************************
``letsencrypt/dnsrecord``
*************************

``GET``
========
Gets DNS challenge records for Let's Encrypt DNS challenge for a specified fqdn.

:Auth. Required: Yes
:Roles Required: "admin" or "operations"
:Response Type:  Object

Request Structure
-----------------
.. table:: Request Query Parameters

	+------+----------+------------------------------------------------------------+
	| Name | Required | Description                                                |
	+======+==========+============================================================+
	| fqdn | yes      | Return only DNS challenge records for the specified fqdn   |
	+------+----------+------------------------------------------------------------+

.. code-block:: http
	:caption: Request Example

	GET /api/1.4/letsencrypt/dnsrecord?fqdn=_acme-challenge.demo1.example.com. HTTP/1.1
	Host: trafficops.infra.ciab.test
	User-Agent: curl/7.47.0
	Accept: */*
	Cookie: mojolicious=...


Response Structure
------------------
.. code-block:: http
	:caption: Response Example

	HTTP/1.1 200 OK
	Content-Type: application/json

	{ "response": {
		"fqdn":"_acme-challenge.demo1.example.com.",
		"record":"testRecord"
	}}