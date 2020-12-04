# encoding: UTF-8

control 'V-81495' do
  title 'Disable TLS RC4 cipher in .Net'
  desc  "Use of the RC4 cipher in TLS could allow an attacker to perform
man-in-the-middle attacks and recover plaintext from encrypted sessions.
Applications that target .Net version 4.x running on multiple Windows versions
could be vulnerable to these types of attacks. The registry settings in this
requirement will prevent .Net applications that target the 4.x framework from
selecting and utilizing the Schannel.dll RC4 cipher for TLS connections.
Applications that use TLS when connecting to remote systems will perform a
handshake and negotiate the TLS version and cipher that is to be used between
the client and the server. This is standard protocol for all TLS connections.
If the server and client are not configured to use the same TLS version and
cipher, the TLS connection may fail. Applications should be tested with these
registry settings prior to production implementation of the fix in order to
avoid application outages."
  desc  'rationale', ''
  desc  'check', "
    Use regedit to review the following Windows registry keys:

    For 32-bit systems:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\\

    For 64 bit systems:

HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework\\v4.0.30319\\

    If the “SchUseStrongCrypto” value name does not exist, or is not a
REG_DWORD type set to “1”, this is a finding.


  "
  desc  'fix', "
    Use regedit to access the following registry key.

    For 32-bit systems:
    HKEY_LOCAL_MACHINE\\SOFTWARE\\Microsoft\\.NETFramework\\v4.0.30319\\

    For 64-bit systems:
HKEY_LOCAL_MACHINE\\SOFTWARE\\Wow6432Node\\Microsoft\\.NETFramework\\v4.0.30319\\

    Modify or create the following Windows registry value: SchUseStrongCrypto

    Set SchUseStrongCrypto to a REG_DWORD value of “1”.

  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'APPNET0075 Disable TLS RC4 cipher in .Net'
  tag gid: 'V-81495'
  tag rid: 'SV-96209r2_rule'
  tag stig_id: 'APPNET0075'
  tag fix_id: 'F-88319r3_fix'
  tag cci: ['CCI-001762']
  tag nist: ['CM-7 (1) (b)']
  tag responsibility: 'System Administrator'
end

