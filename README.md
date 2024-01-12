## Description ##
This plugin enables user authentication and Single Sign-On via [Google](https://google.com/).
It is heavily based on the code by [Julien Lancelot](https://github.com/SonarQubeCommunity/sonar-auth-bitbucket)
Compatible with SonarQube version 5.6 and higher.

## Feedback Process ##
* [Releases](releases/) are created with every SNAPSHOT, but only non-SNAPSHOT releases are added to the Update Center
* Snapshot releases are up for acquia consumption

## Installation ##
1. Update the SonarQube values.yaml with the latest github release url for the plugin jar.
1. Restart the SonarQube server

## Usage ##
In the [Google Developers Console](https://console.developers.google.com/):
1. Go to "Credentials"
2. Click on the "Create credentials" drop-down, and select "OAuth client ID"
3. Set the "Application type" to "Web application"
4. Set the "Name" value to something which you will associated with SonarQube
5. Set the "Authorized JavaScript origins" to the base URL of your SonarQube server web application (no path allowed)
6. Set the "Authorized redirect URIs" to be:
   * ${sonarBaseURL}/oauth2/callback/googleoauth

In SonarQube settings :
1. Go to "Security" -> "Google"
2. Set the "Enabled" property to true
3. Set Google authentication URI: https://accounts.google.com/o/oauth2/v2/auth
4. Set the "OAuth client ID" from the value provided by the Google OAuth consumer
5. Set the "OAuth consumer Secret" from the value provided by the Google OAuth consumer

Go to the login form, a new button "Log in with Google" allow users to connect to SonarQube with their Google accounts.

> Note: Only HTTPS is supported
> * SonarQube must be publicly accessible through HTTPS only
> * The property 'sonar.core.serverBaseURL' must be set to this public HTTPS URL

## General Configuration ##

Property                                   | Description | Default value
-------------------------------------------| ----------- | -------------
sonar.auth.googleoauth.allowUsersToSignUp  |Allow new users to authenticate. When set to 'false', only existing users will be able to authenticate to the server|true
sonar.auth.googleoauth.clientId.secured    |Consumer Key provided by Google when registering the consumer|None
sonar.auth.googleoauth.clientSecret.secured|Consumer password provided by Google when registering the consumer|None
sonar.auth.googleoauth.enabled             |Enable Google users to login. Value is ignored if consumer Key and Secret are not defined|false
sonar.auth.googleoauth.loginStrategy       |When the login strategy is set to 'Unique', the user's login will be auto-generated the first time so that it is unique. When the login strategy is set to 'Same as Google login', the user's login will be the Google login. This last strategy allows, when changing the authentication provider, to keep existing users (if logins from new provider are the same than Google)|Unique
sonar.auth.googleoauth.limitOauthDomain    |When set with a GApps domain, only allow users from that domain to authenticate. Can be a list by separating domains with ","|None

## Auto GitHub Tag Creation

Ensure you have [gh-cli](https://github.com/cli/cli/tree/v2.14.4#macos) installed and [configured](https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/creating-a-personal-access-token) on your local before running the auto tag creation.
Verify if `GITHUB_TOKEN` envVar is set and `gh auth status` cmd output looks green.

Ensure your user has been added as a collaborator on this repository.

Script helps in automating the creation of tags. It accepts a variable `NEW_TAG_VERSION`
which can be used to create tags based on the magnitude of change we have merged to the **main/master/default** branch. The valid values
for this variable are either of `major`, `minor` and `patch`. For more details visit - https://semver.org/

Once the **PullRequest** is approved and merged. We can auto-generate the tag from the main branch and this triggers an auto GitHub Release as well.
The GitHub Tag creation follows the semantic versioning and cuts an appropriate tag from main branch.

Following are the steps to be followed:

```bash
> git checkout main && git pull

> sh auto_create_tag.sh $(NEW_TAG_VERSION)
Selected version is patch
Retrieved current version v1.0.0
Current Version: v1.0.0
(patch) updating v1.0.0 to v1.0.1-rc.0
Retrieved GIT Commit - 570c05e78bf1e1b21c74d72cb9c3b3b8c017e2ac
Tagged with v1.0.1-rc.0
Total 0 (delta 0), reused 0 (delta 0), pack-reused 0
To github.com:acquia/is-metrics-server.git
 * [new tag]         v1.0.1-rc.0 -> v1.0.1-rc.0
```

On checking GitHub now you should see a tag immediately and after a couple of minutes a release auto-generated under the repository.
