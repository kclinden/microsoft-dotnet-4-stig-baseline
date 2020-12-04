# encoding: UTF-8

control 'V-7069' do
  title 'CAS and policy configuration files must be backed up.'
  desc  "A successful disaster recovery plan requires that CAS policy and CAS
policy configuration files are identified and included in systems disaster
backup and recovery events.  Documentation regarding the location of system and
application specific CAS policy configuration files and the frequency in which
backups occur is required.  If these files are not identified and the
information is not documented, there is the potential that critical application
configuration files may not be included in disaster recovery events which could
lead to an availability risk."
  desc  'rationale', ''
  desc  'check', "
    Ask the System Administrator if all CAS policy and policy configuration
files are included in the system backup. If they are not, this is a finding.

    Ask the System Administrator if the policy and configuration files are
backed up prior to migration, deployment, and reconfiguration. If they are not,
this is a finding.

    Ask the System Administrator for documentation that shows CAS Policy
configuration files are backed up as part of a disaster recovery plan. If they
have no documentation proving the files are backed up, this is a finding.
  "
  desc  'fix', "
    All CAS policy and policy configuration files must be included in the
system backup.

    All CAS policy and policy configuration files must be backed up prior to
migration, deployment, and reconfiguration.

    CAS policy configuration files must be included in disaster recovery plan
documentation.
  "
  impact 0.5
  tag severity: 'medium'
  tag gtitle: 'APPNET0055 CAS and Policy Config File Backups'
  tag gid: 'V-7069'
  tag rid: 'SV-7452r2_rule'
  tag stig_id: 'APPNET0055'
  tag fix_id: 'F-12610r3_fix'
  tag cci: []
  tag nist: []
  tag responsibility: 'System Administrator'
  tag ia_controls: 'CODB-1, CODB-2'
end

