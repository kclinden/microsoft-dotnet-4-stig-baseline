# encoding: UTF-8

control 'V-7061' do
  title 'The Trust Providers Software Publishing State must be set to 0x23C00.'
  desc  "Microsoft Windows operating systems provide a feature called
Authenticode.  Authenticode technology and its underlying code signing
mechanisms serve to provide a structure to identify software publishers and
ensure that software applications have not been tampered with.  Authenticode
technology relies on digital certificates and is based on Public Key
Cryptography Standards (PKCS) #7 (encrypted key specification), PKCS #10
(certificate request formats), X.509 (certificate specification), and Secure
Hash Algorithm (SHA) and MD5 hash algorithms.

    The manner in which the Authenticode technology validates a certificate and
determines what is considered a valid certificate can be modified to meet the
mission of the Microsoft Windows system.  Each facade of certificate validation
is controlled through the bits that makeup the hexadecimal value for the
Authenticode setting.  An improper setting will allow non-valid certificates to
be accepted and can put the integrity of the system into jeopardy.

    The hexadecimal value of 0x23C00 will implement the following certificate
enforcement policy:
    - Trust the Test Root = FALSE
    - Use expiration date on certificates = TRUE
    - Check the revocation list = TRUE
    - Offline revocation server OK (Individual) = TRUE
    - Offline revocation server OK (Commercial) = TRUE
    - Java offline revocation server OK (Individual) = TRUE
    - Java offline revocation server OK (Commercial) = TRUE
    - Invalidate version 1 signed objects = FALSE
    - Check the revocation list on Time Stamp Signer = FALSE
    - Only trust items found in the Trust DB = FALSE

  "
  desc  'rationale', ''
  desc  'check', "
    If the system or application being reviewed is SIPR based, this finding is
NA.

    This check must be performed for each user on the system.

    Use regedit to locate \"HKEY_USER\\[UNIQUE USER SID
VALUE]\\Software\\Microsoft\\Windows\\CurrentVersion\\WinTrust\\Trust
Providers\\Software Publishing\\State\".

    If the State value for any user is not set to the hexadecimal value of
0x23C00, this is a finding.

  "
  desc  'fix', "
    This fix must be performed for each user on the system.

    Using regedit, change the hexadecimal value of the \"HKEY_USER\\[UNIQUE
USER SID VALUE]\\Software\\Microsoft\\Windows\\CurrentVersion\\WinTrust\\Trust
Providers\\Software Publishing\\State\" registry key to 0x23C00.

  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'APPNET0046 Test Root certificates'
  tag gid: 'V-7061'
  tag rid: 'SV-7444r3_rule'
  tag stig_id: 'APPNET0046'
  tag fix_id: 'F-12602r12_fix'
  tag cci: []
  tag nist: []
  tag responsibility: 'System Administrator'
end

