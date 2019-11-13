source "https://rubygems.org"
git_source(:github){|repo| "https://github.com/#{repo}.git"}

ruby "2.6.3"

# Bundle edge Rails instead: gem 'rails', github: 'rails/rails'
gem "bootstrap-sass", "3.4.1"
gem "config"
gem "rails", "~> 6.0.0"
gem "faker", "1.7.3"
gem "figaro"
gem "carrierwave", "1.2.2"
gem "will_paginate", "3.1.7"
gem "bootstrap-will_paginate", "1.0.0"
gem "pry"

gem "rails-ujs"
# Use sqlite3 as the database for Active Record
# Use Puma as the app server
gem "puma", "~> 3.11"
# Use SCSS for stylesheets
gem "rails-controller-testing"
gem "sass-rails", "~> 5"
# Transpile app-like JavaScript. Read more: https://github.com/rails/webpacker
gem "webpacker", "~> 4.0"
# Turbolinks makes navigating your web application faster. Read more: https://github.com/turbolinks/turbolinks
gem "turbolinks", "~> 5"
# Build JSON APIs with ease. Read more: https://github.com/rails/jbuilder
gem "jbuilder", "~> 2.7"
gem "jquery-rails"

# Use Redis adapter to run Action Cable in production
gem "rails-i18n"
# gem 'redis', '~> 4.0'
# Use Active Model has_secure_password
gem "bcrypt", "~> 3.1.12"

# Use Active Storage variant
# gem 'image_processing', '~> 1.2'

# Reduces boot times through caching; required in config/boot.rb
gem "bootsnap", ">= 1.4.2", require: false

group :development, :test do
  gem "byebug", platforms: [:mri, :mingw, :x64_mingw]
  gem "rubocop", "~> 0.74.0", require: false
  gem "rubocop-rails", "~> 2.3.2", require: false
  gem "sqlite3"
end

group :development do
  gem "listen", ">= 3.0.5", "< 3.2"
  gem "spring"
  gem "spring-watcher-listen", "~> 2.0.0"
  gem "web-console", ">= 3.3.0"
end

group :test do
  # Adds support for Capybara system testing and selenium driver
  gem "capybara", ">= 2.15"
  gem "selenium-webdriver"
  # Easy installation and use of web drivers to run system tests with browsers
  gem "webdrivers"
end

group :production do
  gem "pg", "0.20.0"
end

# Windows does not include zoneinfo files, so bundle the tzinfo-data gem
gem "tzinfo-data", platforms: [:mingw, :mswin, :x64_mingw, :jruby]
