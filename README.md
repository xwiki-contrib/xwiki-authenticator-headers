Provides XWiki authentication by trusting HTTP Headers and getting information about new users from those same headers.

# This authenticator execute the following process

 1. Check that the _auth_field_ contains a value
    1. get the UserID from the _id_field_ and convert it as described in the configuration.
    2. If this is a new session, or the current user in session is not the actual user:
       1. If the user does not exists
          1. Create a new user
          2. Map all field described in _field_mapping_ into user's properties of that user
       2. If _group_mapping_ is defined, synchronize the membership of that user to match groups provided.
          1. Add user to group provided in the _group_field_ header (as needed)
          2. Remove it from all mapped group not provided in the _group_field_ header (as needed)
    3. The user is authenticated and memorize for the current session.
 2. If no remote user ( _auth_field_ ) is provided, fallback to standard XWiki authentication.

# Configuration

## xwiki.cfg file

    #-# Name of the header field used to check for the authentication of a user.
    #-# The content of this field should not be empty to have this authenticator to proceed, and it will be put
    #-# in the debugging log. But not real usage of this header value is done by the authenticator.
    #-# The default is to use the REMOTE_USER header.
    # xwiki.authentication.headers.auth_field=remote_user
    
    #-# Name of the header field holding the UserID of the authenticated user.
    #-# This name will be used as the unique user name. It will be transformed in lowercase, and it will be
    #-# cleaned by replacing dots (.) by equal signs (=), and replacing at signs (@) by underscores (_).
    #-# For example John.Doe@example.com will became john=doe_example=com.
    #-# The default is to use the REMOTE_USER header.
    # xwiki.authentication.headers.id_field=remote_user
    
    #-# Name of a header field containing a shared secret value.
    #-# While not mandatory, this field is hardly recommended to properly authenticate that headers has not be forged.
    #-# If not set, a warning will remind you in the log, since this is really a risky situation.
    # xwiki.authentication.headers.secret_field=

    #-# The shared secred that should match the content of the shared secret header field.
    # xwiki.authentication.headers.secret_value= (no default, only used when set)

    #-# Name of a header field holding the list of group the user is a member of.
    #-# If not configure, no group synchronization is provided.
    # xwiki.authentication.headers.group_field=
    
    #-# A separator used to split the list of groups into group names.
    #-# Default to the pipe character.
    # xwiki.authentication.headers.group_value_separator=|
    
    #-# Mapping between group names found in the list of groups and XWiki groups.
    # xwiki.authentication.headers.groups_mapping=groupA=XWiki.XWikiGroupA,groupB=XWiki.XWikiGroupB

    #-# Mapping between header fields and XWiki users fields.
    # xwiki.authentication.headers.fields_mapping=email=mail,first_name=givenname,last_name=sn

# Install

* copy this authenticator jar file into WEB_INF/lib/
* setup xwiki.cfg with: xwiki.authentication.authclass=com.xwiki.authentication.headers.XWikiHeadersAuthenticator

# Troubleshoot

## Debug log

    <!-- Header authenticator debugging -->
    <logger name="com.xwiki.authentication.headers.XWikiHeadersAuthenticator" level="debug"/>

See http://platform.xwiki.org/xwiki/bin/view/AdminGuide/Logging for general information about logging in XWiki.
