# encoding: UTF-8

control 'V-31026' do
  title "Event tracing for Windows (ETW) for Common Language Runtime events
must be enabled."
  desc  "Event tracing captures information about applications utilizing the
.NET CLR and the .NET CLR itself. This includes security oriented information,
such as Strong Name and Authenticode verification.

    Beginning with Windows Vista, ETW is enabled by default however, the .Net
CLR and .Net applications can be configured to not utilize Event Tracing. If
ETW event tracing is disabled, critical events that occurred within the runtime
will not be captured in event logs.
  "
  desc  'rationale', ''
  desc  'check', "
    Open Windows explorer and search for all .NET config files including
application config files (*.exe.config)

    NOTE:
    Beginning with Windows Vista and Windows Server 2008, ETW Tracing is
enabled by default and the \"etwEnable\" setting is not required in order for
Event Tracing to be enabled.  An etwEnable setting of \"true\" IS required in
earlier versions of Windows as ETW is disabled by default.

    Examine the configuration settings for
    <etwEnable enabled=\"false\" />.

    If the \"etwEnable\" element is set to \"true\", this is not a finding.

    If the \"etwEnable\" element is set to \"false\" and documented approvals
by the IAO are not provided, this is a finding.

  "
  desc  'fix', "
    Open Windows explorer and search for all .NET config files including
application config files (*.exe.config).

    Examine the configuration settings for
    <etwEnable enabled=\"false\" />.

    Enable ETW Tracing by setting the etwEnable flag to \"true\" or obtain
documented IAO approvals.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'APPNET0067 .NET Event Tracing for Windows.'
  tag gid: 'V-31026'
  tag rid: 'SV-41075r1_rule'
  tag stig_id: 'APPNET0067'
  tag fix_id: 'F-34847r6_fix'
  tag cci: []
  tag nist: []
  tag ia_controls: 'DCSL-1'
end

