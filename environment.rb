require 'bundler'
Bundler.require(:default)
ROOT = File.dirname(__FILE__)

Dir[File.join(ROOT, 'garrison/lib/*.rb')].each do |file|
  require file
end

Dir[File.join(ROOT, 'garrison/checks/*.rb')].each do |file|
  require file
end

Garrison::Api.configure do |config|
  config.url = ENV['GARRISON_URL']
end

Garrison::Logging.info('Garrison Agent - AWS GuardDuty')

module Garrison
  module Checks
    @options = {}
    @options[:regions] = ENV['GARRISON_AWS_REGIONS'] ? ENV['GARRISON_AWS_REGIONS'].split(',') : nil
  end
end
