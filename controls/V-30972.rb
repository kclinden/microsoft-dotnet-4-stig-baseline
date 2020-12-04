# encoding: UTF-8

control 'V-30972' do
  title '.NET default proxy settings must be reviewed and approved.'
  desc  "The .Net framework can be configured to utilize a different proxy or
altogether bypass the default proxy settings in the client's browser.  This may
lead to the framework using a proxy that is not approved for use.  If the proxy
is malicious, this could lead to a loss of application integrity and
confidentiality."
  desc  'rationale', ''
  desc  'check', "
    Open Windows explorer and search for all \"*.exe.config\" and
\"machine.config\" files.

    Search each file for the \"defaultProxy\" element.

    <defaultProxy
      enabled=\"true|false\"
      useDefaultCredentials=\"true|false\"
      <bypasslist> … </bypasslist>
      <proxy> … </proxy>
      <module> … </module>
    />

    If the \"defaultProxy\" setting \"enabled=false\" or if the \"bypasslist\",
\"module\", or \"proxy\" child elements have configuration entries and there
are no documented approvals from the IAO, this is a finding.

    If the \"defaultProxy\" element is empty then the framework is using
default browser settings, this is not a finding.


  "
  desc  'fix', "
    Open Windows explorer and search for all \"*.exe.config\" and
\"machine.config\" files.

    Search each file for the \"defaultProxy\" element.

    Clear the values contained in the \"defaultProxy\" element, and the
\"bypasslist\", \"module\", and \"proxy\" child elements.

    The IAO must provide documented approvals of any non-default proxy servers.
  "
  impact 0.3
  tag severity: 'low'
  tag gtitle: 'APPNET0066 .Net Default Proxy Settings'
  tag gid: 'V-30972'
  tag rid: 'SV-41014r1_rule'
  tag stig_id: 'APPNET0066'
  tag fix_id: 'F-34785r7_fix'
  tag cci: []
  tag nist: []
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCFA-1, DCSL-1'
end

