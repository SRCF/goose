from ucam_wls import load_private_key

# Flask debug mode.  Your webapp will be vulnerable if it is available to the
# public in debug mode.
DEBUG = False

# There is no security offered if TESTING is enabled.
# If TESTING is enabled, then you can log in with usernames 'test0001' to
# 'test0500', and password 'test'.
TESTING = False

# You MUST change this to something random, then do not share it with anyone.
SECRET_KEY = b'correct horse battery staple'

# Customise as you see fit.
WLS_TITLE = "Web login service"
WLS_BRAND_HTML = '''
  <a href="https://www.example.com/">
    <img src="/static/logo.png">
    <span>
      Web login service
    </span>
  </a>
'''

# Key configuration.
#
# WLS_KEYS values must be of type ucam_wls.Key.
# ucam_wls.load_private_key() is a convenient function to use for this, but you
# can of course load by any method you want.
WLS_KEYS = {
    1: load_private_key('/var/lib/goose/privkey1.pem'), kid=1),
}
WLS_USE_KEY = 1
