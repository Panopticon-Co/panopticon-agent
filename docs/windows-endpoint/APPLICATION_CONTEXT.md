# Browser and Office registration context

Two independent native registry workers add browser_registration_inventory and office_addin_inventory. Both preserve the existing bounded raw-value/page/manifest contract, explicit registry view and refusal evidence, and independent committed freshness.

Browser configuration covers selected Chrome/Edge/Chromium external extension registrations, native messaging registrations and mandatory extension/native messaging policy lists/settings, plus Firefox native messaging host registrations. This reports caller-visible configuration, not installation, execution or effective policy. Profile manifest observations are collected independently by the browser inventory source.

Office configuration covers selected Word, Excel, PowerPoint, Outlook, Access, Visio, Project and OneNote add-in registration fields, and selected Office 15/16 application security registry values in ordinary and policy locations. This does not establish macro execution, document contents, add-in loading or effective protection.

The registry implementation has a fresh native component suite and main-target build from this wave before subsequent collectors were integrated. The final combined executable compiles. These new application sources have no current dedicated guest runtime evidence. Unloaded user hives, every Office/browser version, policy precedence, traversal fairness, deltas and privacy/resource qualification remain open.

References: [Edge forced extensions](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-policies/extensioninstallforcelist), [ExtensionSettings](https://learn.microsoft.com/en-us/deployedge/microsoft-edge-browser-policies/extensionsettings), [VSTO registration](https://learn.microsoft.com/en-us/visualstudio/vsto/registry-entries-for-vsto-add-ins?view=visualstudio).
