# encoding: UTF-8

control 'V-30926' do
  title "The .NET CLR must be configured to use FIPS approved encryption
modules."
  desc  "FIPS encryption is configured via .NET configuration files.  There are
numerous configuration files that affect different aspects of .Net behavior.
The .NET config files are described below.

    Machine Configuration Files:
    The machine configuration file, Machine.config, contains settings that
apply to an entire computer. This file is located in the
%SYSTEMROOT%\\Microsoft.NET\\Framework\\v4.0.30319\\Config directory for 32 bit
.NET 4 installations and
%SYSTEMROOT%\\Microsoft.NET\\Framework64\\v4.0.30319\\Config for 64 bit
systems.   Machine.config contains configuration settings for machine-wide
assembly binding, built-in remoting channels, and ASP.NET.

    Application Configuration Files:
    Application configuration files contain settings specific to an
application. If checking these files, a .NET review of a specific .NET
application is most likely being conducted. These files contain configuration
settings that the Common Language Runtime reads (such as assembly binding
policy, remoting objects, and so on), and settings that the application can
read.

    The name and location of the application configuration file depends on the
application's host, which can be one of the following:

    Executable–hosted application configuration files.

    The configuration file for an application hosted by the executable host is
in the same directory as the application. The name of the configuration file is
the name of the application with a .config extension. For example, an
application called myApp.exe can be associated with a configuration file called
myApp.exe.config.

    Internet Explorer-hosted application configuration files.

    If an application hosted in Internet Explorer has a configuration file, the
location of this file is specified in a <link> tag with the following
syntax.

    <link rel=\"ConfigurationFileName\" href=\"location\">

    In this tag, \"location\" represents a URL that point to the configuration
file. This sets the application base. The configuration file must be located on
the same web site as the application.

    .NET 4.0 allows the CLR runtime to be configured to ignore FIPS encryption
requirements.  If the CLR is not configured to use FIPS encryption modules,
insecure encryption modules might be employed which could introduce an
application confidentiality or integrity issue.

  "
  desc  'rationale', ''
  desc  'check', "

    Examine the .NET CLR configuration files from the vulnerability discussion
to find the runtime element and then the \"enforceFIPSPolicy\" element.

    Example:
    <configuration>
      <runtime>
                    <enforceFIPSPolicy enabled=\"true|false\" />
      </runtime>
    </configuration>

    By default, the .NET \"enforceFIPSPolicy\" element is set to \"true\".

    If the \"enforceFIPSPolicy\" element does not exist within the \"runtime\"
element of the CLR configuration, this is not a finding.

    If the \"enforceFIPSPolicy\" element exists and is set to \"false\", and
the IAO has not accepted the risk and documented the risk acceptance, this is a
finding.


  "
  desc  'fix', "
    Examine the .NET CLR configuration files to find the runtime element and
then the \"enforceFIPSPolicy\" element.

    Example:
    <configuration>
      <runtime>
                    <enforceFIPSPolicy enabled=\"true|false\" />
      </runtime>
    </configuration>

    Delete the \"enforceFIPSPolicy\" runtime element, change the setting to
\"true\" or there must be documented IAO approvals for the FIPS setting.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'APPNET0062 Administering FIPS Policy'
  tag gid: 'V-30926'
  tag rid: 'SV-40966r1_rule'
  tag stig_id: 'APPNET0062'
  tag fix_id: 'F-34734r4_fix'
  tag cci: []
  tag nist: []
  tag responsibility: 'System Administrator'
  tag ia_controls: 'DCNR-1'
end

