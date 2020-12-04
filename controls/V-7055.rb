# encoding: UTF-8

control 'V-7055' do
  title "Digital signatures assigned to strongly named assemblies must be
verified."
  desc  "A strong name consists of the assembly's identity, simple text name,
version number, and culture information (if provided)—plus a public key and a
digital signature.  Strong names serve to identify the author of the code.  If
digital signatures used to sign strong name assemblies are not verified, any
self signed code can be impersonated.  This can lead to a loss of system
integrity. "
  desc  'rationale', ''
  desc  'check', "
    Use regedit to review the Windows registry key
    HKLM\\Software\\Microsoft\\StrongName\\Verification.
    There should be no assemblies or hash values listed under this registry
key. If the StrongName\\Verification key does not exist, this is not a finding.

    If there are assemblies or hash values listed in this key, each value
represents a distinct application assembly that does not have the application
strong name verified.

    If any assemblies are listed as omitting strong name verification in a
production environment, this is a finding.

    If any assemblies are listed as omitting strong name verification in a
development or test environment and the IAO has not provided documented
approvals, this is a finding.
  "
  desc  'fix', "
    Use regedit to remove the values stored in Windows registry key
HKLM\\Software\\Microsoft\\StrongName\\Verification. There should be no
assemblies or hash values listed under this registry key.

    All assemblies must require strong name verification in a production
environment.

    Strong name assemblies that do not require verification in a development or
test environment must have documented approvals from the IAO.

  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'APPNET0031 No Strong Name Verification'
  tag gid: 'V-7055'
  tag rid: 'SV-7438r3_rule'
  tag stig_id: 'APPNET0031'
  tag fix_id: 'F-12596r7_fix'
  tag cci: []
  tag nist: []
  tag responsibility: 'System Administrator'
end

