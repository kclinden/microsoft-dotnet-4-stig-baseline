# encoding: UTF-8

control 'V-30968' do
  title "Trust must be established prior to enabling the loading of remote code
in .Net 4."
  desc  "In the .NET Framework version 3.5 and earlier versions, if an
application assembly loaded code/objects from a remote location, that assembly
would run partially trusted with a permissions grant set that depended on the
zone in which it was loaded. For example, if an assembly was loaded from a web
site, it was loaded into the Internet zone and granted the Internet permission
set. In other words, it was executed in an Internet sandbox.

    If the same program is run in the .NET Framework version 4, an exception is
thrown which effectively states; either explicitly create a sandbox for the
assembly or run it in full trust.

    The LESSloadFromRemoteSourcesGREAT element specifies the assemblies that
run partially trusted in earlier versions of the .NET Framework will be run
fully trusted in the .NET Framework 4.

    If loadFromRemoteSources is set to true, the remotely loaded application
code is granted full trust.  This could create an integrity vulnerability on
the system.  The required method to address this is to explicitly create a
sandboxed environment for the remotely loaded code to run in rather than
allowing remotely loaded code to run with full trust.

    The appropriate level of trust must be established prior to enabling the
loading of remote code in .Net 4 applications and that code must be run in a
controlled environment.  The following is an example of the use of
loadFromRemoteSources.

    LESSconfigurationGREAT
    LESSruntimeGREAT
        LESSloadFromRemoteSources enabled=\"true\" \"https://my.dodorg.gov\"
/GREAT
        LESSloadFromRemoteSources enabled=\"true\" \"https://192.168.0.*\"
/GREAT
        LESSloadFromRemoteSources enabled=\"false\" \"*\" /GREAT
    LESS/runtimeGREAT
    LESS/configurationGREAT

  "
  desc  'rationale', ''
  desc  'check', "
    Open Windows explorer and search for *.exe.config.

    Search each config file found for the \"loadFromRemoteSources\" element.

    If the loadFromRemoteSources element is enabled
    (\"loadFromRemoteSources enabled = true\"), and the remotely loaded
application is not run in a sandboxed environment, or if OS based software
controls, such as AppLocker or Software Security Policies, are not utilized,
this is a finding.

  "
  desc  'fix', "
    .Net application code loaded from a remote source must be run in a
controlled environment.

    A controlled environment consists of a sandbox, such as running in an
Internet Explorer host environment or employing OS based software access
controls, such as AppLocker or Software Security Policies, when application
design permits.

    Obtain documented IAO approvals for all remotely loaded code.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'APPNET0065 Load From Remote Sources'
  tag gid: 'V-30968'
  tag rid: 'SV-41010r1_rule'
  tag stig_id: 'APPNET0065'
  tag fix_id: 'F-34779r3_fix'
  tag cci: []
  tag nist: []
  tag responsibility: 'Systems Programmer'
end

