module Garrison
  module Checks
    class CheckFindings < Check

      def settings
        self.source ||= 'aws-guardduty'
        self.family ||= 'attack'
        self.type ||= 'security'
        self.options[:regions] ||= 'all'
      end

      def key_values
        [
          { key: 'datacenter',  value: 'aws' },
          { key: 'aws-service', value: 'guardduty' }
        ]
      end

      def perform
        options[:regions] = AwsHelper.all_regions if options[:regions] == 'all'
        options[:regions].each do |region|
          Logging.info "Checking region #{region}"
          gd = Aws::GuardDuty::Client.new(region: region)
          next unless AwsHelper.guardduty_enabled?(gd)

          AwsHelper.guardduty_list_findings(gd).each do |finding|
            next if finding.service.archived
            alert(
              name: finding.type.gsub(':', ': ').gsub('/', ' - '),
              target: resource_identifier(finding.resource),
              detail: finding.title,
              no_repeat: true,
              finding: finding.to_h.to_json,
              finding_id: finding.id,
              first_detected_at: finding.service.event_first_seen,
              last_detected_at: finding.service.event_last_seen,
              count: finding.service.count,
              external_severity: aws_severity_to_garrison_severity(finding.severity),
              urls: [
                {
                  name: 'AWS Dashboard',
                  url: "https://console.aws.amazon.com/guardduty/home?region=#{finding.region}"
                }
              ],
              key_values: [
                {
                  key: 'aws-account',
                  value: finding.account_id
                },
                {
                  key: 'aws-region',
                  value: finding.region
                }
              ]
            )
          end
        end
      end

      private

      def resource_identifier(resource)
        if resource.resource_type == 'AccessKey'
          resource.access_key_details.access_key_id
        elsif resource.resource_type == 'Instance'
          resource.instance_details.instance_id
        end
      end

      def aws_severity_to_garrison_severity(severity)
        case severity
        when 8.0
          'critical'
        when 5.0
          'medium'
        when 2.0
          'low'
        end
      end

    end
  end
end
