# Windows Security Center product registrations

The independent `security_product_inventory` worker reads Windows Security
Center's `IWSCProductList` for the firewall, antivirus and antispyware provider
types. It retains bounded product name, provider product GUID, remediation path,
product-state timestamp, reported product state, reported signature status, and
the provider's default-product flag. Each getter and category enumeration keeps
its exact HRESULT. Individual strings are capped at 4 KiB and 64 KiB per
product; enumeration is capped at 64 products per category. Unknown enum values,
null outputs, failed getters, refusal and bounds stay explicit. Product capture
is included as a canonical state record, retried with identical bytes until the
journal accepts it, and health is bound to that accepted record and five-minute
freshness window.

Microsoft documents `IWSCProduct` as a way to retrieve an individual registered
product and documents its state, signature status, timestamp, remediation path,
GUID, and default flag. This is Windows Security Center's caller-visible
registration report, not independent product verification. A reported `on`
state or `up_to_date` signature status does not prove the product is active,
trusted, tamper-protected, or enforcing. The provider GUID and name are claims
from the local WSC interface; Panopticon does not validate the product binary,
signer, install path, live service, or effective protection.

The API contract documents Windows 8 or later desktop clients and no supported
Windows Server contract. The collector still attempts read-only collection
where installed, but does not claim platform qualification. Missing COM
registration, provider/API refusal, out-of-contract behavior and empty product
lists remain distinct from a verified absence of security software. Native COM
calls have no hard deadline; the caller-visible list may omit products and
provides no complete coverage guarantee. Product names and remediation paths
are retained as endpoint security configuration data; remediation paths are
never executed.

References: [IWscProduct](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/nn-iwscapi-iwscproduct),
[IWSCProductList](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/nn-iwscapi-iwscproductlist),
[IWSCProductList::Initialize](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/nf-iwscapi-iwscproductlist-initialize),
[IWSCProductList::get_Item](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/nf-iwscapi-iwscproductlist-get_item),
[IWscProduct::get_ProductState](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/nf-iwscapi-iwscproduct-get_productstate),
[IWscProduct::get_SignatureStatus](https://learn.microsoft.com/en-us/windows/win32/api/iwscapi/nf-iwscapi-iwscproduct-get_signaturestatus).

This source addition has not been built, component-tested or run on Windows.
The final integration stage must verify category enumeration, empty/provider
refusal behavior, HRESULT and enum decoding, record durability/replay, health
freshness, privacy and Windows client/server differences on the owned VM.
