#!/bin/bash

VERSION=$1

echo "Selected version is $VERSION"

#get highest tag number, and add 1.0.0 if doesn't exist
CURRENT_VERSION=$(gh release view --json tagName -q .tagName)
echo "Retrieved current version $CURRENT_VERSION"

if [[ $CURRENT_VERSION == '' ]]
then
  CURRENT_VERSION='v0.0.0'
fi
echo "Current Version: $CURRENT_VERSION"

#replace . with space so can split into an array
CURRENT_VERSION_PARTS=(${CURRENT_VERSION//./ })

#get number parts
VNUM1=(${CURRENT_VERSION_PARTS[0]//v/})
VNUM2=${CURRENT_VERSION_PARTS[1]}
VNUM3=${CURRENT_VERSION_PARTS[2]}

if [[ $VERSION == 'major' ]]
then
  VNUM1=$((VNUM1+1))
  VNUM2=0
  VNUM3=0
elif [[ $VERSION == 'minor' ]]
then
  VNUM2=$((VNUM2+1))
  VNUM3=0
elif [[ $VERSION == 'patch' ]]
then
  VNUM3=$((VNUM3+1))
else
  echo "No version type (https://semver.org/) or incorrect type specified, try: -v [major, minor, patch]"
  exit 1
fi


#create new tag
NEW_TAG="v$VNUM1.$VNUM2.$VNUM3"
echo "($VERSION) updating $CURRENT_VERSION to $NEW_TAG"

#get current hash and see if it already has a tag
GIT_COMMIT=$(git rev-parse HEAD)
NEEDS_TAG=$(git describe --contains $GIT_COMMIT 2>/dev/null)

echo "Retrieved GIT Commit - $GIT_COMMIT"

#only tag if no tag already
if [ -z "$NEEDS_TAG" ]; then
    git tag $NEW_TAG
    echo "Tagged with $NEW_TAG"
    git push origin --tags
    gh repo set-default acquia-infra-services/sonar-auth-google
    gh release create $NEW_TAG ./target/sonar-auth-googleoauth-plugin*.jar --generate-notes
else
  echo "Already a tag on this commit"
fi

exit 0
