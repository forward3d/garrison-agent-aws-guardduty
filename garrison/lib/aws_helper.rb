module Garrison
  class AwsHelper

    def self.whoami
      @whoami ||= Aws::STS::Client.new(region: 'us-east-1').get_caller_identity
    end

    def self.all_regions
      Aws.partition('aws').regions.map(&:name)
    end

    def self.guardduty_enabled?(gd)
      Logging.debug 'AWS SDK - Listing Detectors'
      detectors = gd.list_detectors.detector_ids.map do |id|
        gd.get_detector(detector_id: id)
      end
      detectors.select { |d| d.status == 'ENABLED' }.count > 0
    end

    def self.guardduty_list_findings(gd)
      Logging.debug 'AWS SDK - Pulling all findings'

      # you can only have one detector in a region, but they are returned
      # as arrays, so just assume there might be more in future
      gd.list_detectors.detector_ids.map do |detector|
        list_all_findings(gd, detector).to_a
      end.flatten
    end

    private

    def self.list_all_findings(gd, detector_id)
      Enumerator.new do |yielder|
        next_token = ''

        loop do
          Logging.debug "AWS SDK - Listings Findings (detector_id=#{detector_id} next_token=#{next_token})"
          results = gd.list_findings(detector_id: detector_id, next_token: next_token)

          Logging.debug "AWS SDK - Realizing Findings (detector_id=#{detector_id} count=#{results.finding_ids.count})"
          findings = gd.get_findings(detector_id: detector_id, finding_ids: results.finding_ids)
          findings.findings.map { |item| yielder << item }

          if results.next_token != ''
            next_token = results.next_token
          else
            raise StopIteration
          end
        end
      end.lazy
    end

  end
end
