# Active Directory for K8TRE

Having a kerberos identity which is specific to a user-project pair
helps ensure project separation on shared resources, such as a
Microsoft SQL Server. The same itentity can also be used for other
services, such as CIFS file sharing or accessing internal websites.

There are a few main parts:

* The Samba Service, configured as a domain controller.
* The Keytab generator task.
