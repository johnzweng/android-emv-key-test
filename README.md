# EMV-Card ROCA-Keytest 
 
### What's this?
This is a simple Android app, which reads (NFC-enabled) EMV banking cards via NFC,
tries to extract the **public** RSA keys (ICC, issuer and card-scheme CA),
and displays the data in hexdecimal form.

The keys are also checked for the
[ROCA vulnerability](https://crocs.fi.muni.cz/public/papers/rsa_ccs17)
(see also the note below).


##### Source details
If you want to see how the EMV public keys are recovered from certificates
look into [EMVKeyReader.java](app/src/main/java/at/zweng/emv/keys/EmvKeyReader.java).


The check for the ROCA vulnerability is done in
[ROCACheck.java](app/src/main/java/at/zweng/emv/keys/checks/ROCACheck.java)
which is based on the code from the
[crocs-muni/roca github repository](https://github.com/crocs-muni/roca/blob/master/java/BrokenKey.java)
where credits for porting it to Java go to [Martin Paljak](https://github.com/martinpaljak).


### Download APK:
A readily built APK file can be found in the release section
(direct download link: [EMV-Key-Test-1.0.0.apk](https://github.com/johnzweng/android-emv-key-test/releases/download/1.0.0/EMV-Key-Test-1.0.0.apk)).

### TODO / not working:
- get a nice logo
- Currently the ICC PIN Encipherment RSA key (if present) is not checked
  (mostly because I don't have a card with such a key for testing)
- the hash within the ICC public key certificate is not checked for
  validity (currently I didn't implement full data verification of all
  static authentication data)



### Notes regarding ROCA vulnerability and EMV:
I would expect that EMV RSA keys are NOT vulnerable to the ROCA attack,
because as far as I understand the EMVCo documents the RSA keys used in
payment cards are created externally and then loaded into the payment
card during card personalization using well-defined procedures.
So the RSA keys are not generated within the payment card.

The ROCA vulnerability only affects keys generated **within**
certain Infineon chips (when the "*RSA Library v1.02.013*" was used).

So as far as I understand, EMV RSA keys should not be vulnerable to ROCA.
But you can check your cards yourself with this app.

I built this app to learn more about EMV certificate chain verification
and for fun. :-)


### Credits
This app uses code from
[Julien Millau's EMV-NFC-Paycard-Enrollment library](https://github.com/devnied/EMV-NFC-Paycard-Enrollment) for parsing
EMV cards. The library is included as source as I modified it a little bit
to get the key-related data fields (which it didn't read by default).

