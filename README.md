# EMV-Card ROCA-Keytest 
 
### What's this?
This is a simple Android app, reads (NFC-enabled) EMV cards via NFC, extracts the public (RSA) keys
(ICC, issuer and card-scheme CA), and checks them for ROCA vulnerability 
(https://crocs.fi.muni.cz/public/papers/rsa_ccs17).
 
 
This app uses code from 
[Julien Millau's EMV-NFC-Paycard-Enrollment library](https://github.com/devnied/EMV-NFC-Paycard-Enrollment) for parsing 
EMV cards.


### Note:
I would expect that EMV RSA keys are NOT vulnerable for the ROCA attack, as per EMVCo specifications RSA keys used in 
payment cards should be created externally and then loaded into the payment card during card personalization using 
a well-defined procedure. So the RSA keys are not generated within the payment card.

The ROCA vulnerability only affects keys generated within certain Infineon chips by using the Infineon-developed 
"RSA Library version v1.02.013".

So this app should be useless (and should always report that keys are safe).
I do it nevertheless to learn more about EMV certificate chain verification and for fun. :-)
