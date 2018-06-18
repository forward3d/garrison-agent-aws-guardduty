module Garrison
  module Checks
    class CheckEnabled < Check

      def settings
        self.source ||= 'aws-guardduty'
        self.severity ||= 'critical'
        self.family ||= 'infrastructure'
        self.type ||= 'compliance'
        self.options[:regions] ||= 'all'
      end

      def key_values
        [
          { key: 'datacenter', value: 'aws' },
          { key: 'aws-service', value: 'guardduty' },
          { key: 'aws-account', value: AwsHelper.whoami.account }
        ]
      end

      def perform
        options[:regions] = AwsHelper.all_regions if options[:regions] == 'all'
        options[:regions].each do |region|
          Logging.info "Checking region #{region}"
          gd = Aws::GuardDuty::Client.new(region: region)
          next if AwsHelper.guardduty_enabled?(gd)
          alert(
            name: 'GuardDuty Violation',
            target: region,
            detail: 'not enabled',
            finding: {}.to_json,
            no_repeat: true,
            finding_id: "aws-gd-#{AwsHelper.whoami.account}-#{region}-enabled",
            urls: [
              {
                name: 'AWS Dashboard',
                url: "https://console.aws.amazon.com/guardduty/home?region=#{region}"
              }
            ],
            key_values: [
              {
                key: 'aws-region',
                value: region
              }
            ]
          )
        end
      end

    end
  end
end
