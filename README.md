# NTLMInjector
In case you didn't now how to restore the user password after you have done a user password resset
(Reminder: get the hash previous with DCSync as domain admin)

Right required: user reset password (no domain admin)
Works remotely

Done using SamSetInformationUser(SAMPR_USER_INTERNAL1_INFORMATION)

Know caveat:
Kerberos AES256 (and other special keys) not changed
