# SRCF Goose

Code: <https://github.com/srcf/goose>  
Production server: <https://auth.srcf.net/>

Goose is a web login service run by the [SRCF](https://www.srcf.net/), mainly
for internal use, but it is open to any interested parties if they would like to
authenticate users who have SRCF and/or [Raven](https://raven.cam.ac.uk/)
accounts.

# How to use Goose

## As a principal

A **principal** is someone who is being authenticated, _i.e._\ someone who is
proving their identity in order to access resources or have their identity
verified by Goose to another website, and probably using a username and
password.  This will be the majority of people using Goose.

You do not need to do anything special if you fall into this category: just
follow the instructions provided by Goose to log in with your SRCF account or
Raven account.  You will be sent to Goose by a web application that relies on it
for authentication.

## As a website administrator

If your website supports Raven, it can support Goose without much effort.  You
just need to set the following configuration options in your web application:

  - Login URL: `https://auth.srcf.net/wls/authenticate`
  - Logout URL: `https://auth.srcf.net/logout`
  - Key ID: 500
  - Key file: currently available on request from <sysadmins@srcf.net>

Refer to the documentation for your WAA (web authentication agent) module or
library on how to configure these parameters.

We intend to make Goose's public key 500 generally available for download when
the service has undergone more testing (both from the SRCF and by existing
relying websites) and when the service's behaviour is more stable.  At that
stage you should be able to start using Goose to authenticate your users without
needing to contact us ahead of time.

# Contributing and acknowledgements

Contributions to Goose are welcome from anyone.  By contributing you assert that
you hold copyright for your contributions, and that as copyright holder you
agree for your changes to be available to the public under the MIT License,
whose terms are laid out in [COPYING](COPYING).

The 'Father of Raven', and designer of the WAA2WLS protocol, is Jon Warbrick. We
wouldn't have bothered making Goose ourselves if a simple and reliable system
such as Raven hadn't existed as inspiration in the first place.
