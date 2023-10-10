## 1st-ZTA-of-HYOK-or-BYOK-KMI-with-Certified-HSM-based-DKE-for-Critical-DPI-v001.py
## 1st-ZTA-of-VSS(Verifiable-Secret-Sharing)-CoSi(Collective-Signing)-EdDSA-MultiSig-with-DKE-Vault-KMI.py
## 1st-ZTA-of-VSS-CoSi-EdDSA-MultiSig-with-DKE-Vault-KMI-v001.py

```
Python code snippet that uses the HVAC and Cryptography libraries to implement
a PoC for HYOC HSM based Double Key Encryption of MultiSig with CoSi, such as described in the LinkedIn post:
https://www.linkedin.com/feed/update/urn:li:activity:7117123168456056832?commentUrn=urn%3Ali%3Acomment%3A%28activity%3A7117123168456056832%2C7117181356823977984%29&dashCommentUrn=urn%3Ali%3Afsd_comment%3A%287117181356823977984%2Curn%3Ali%3Aactivity%3A7117123168456056832%29
(1) 1st-ENU-GBT+23-Scalable-Multi-domain-Trust-KMI-for-Segmented-NWs-2310-04898.pdf
(GBT+23 [Grierson, Buchanan, Thomson, Ghaleb, Maglaras & Eckle @ IEEE CAMAD 2023 @ ENU BIL]
 @ https://arxiv.org/abs/2310.04898 @ https://arxiv-vanity.com/papers/2310.04898
(2) Azure Information Protection with HYOK (Hold Your Own Key). https://techcommunity.microsoft.com/t5/security-compliance-and-identity/azure-information-protection-with-hyok-hold-your-own-key/ba-p/249920.
(3) Double Key Encryption overview and FAQ | Microsoft Learn. https://learn.microsoft.com/en-us/purview/double-key-encryption-overview
(4) Announcing Thales HSM Backed Double Key Encryption for ... - Thales Group. https://cpl.thalesgroup.com/blog/encryption/microsoft-office-365-double-key-encyrption-with-luna-hsm.

 ```


# Import the libraries
import hvac
import cryptography
