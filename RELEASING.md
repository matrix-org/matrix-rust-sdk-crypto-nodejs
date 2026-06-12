# Steps for releasing `matrix-rust-sdk-crypto-nodejs`

1. Create a new branch, named `release-v<version>`.
2. Replace the "UNRELEASED" heading in `CHANGELOG.md` with the new version
   number, start a new (empty) "UNRELEASED" section, and commit your changes
   ready for the next step, as pnpm will require a clean working tree.
3. Run `pnpm version <version> -m "v%s"`, where `<version>` is your desired new version.
   You can use `major`/`minor`/`patch` as a shorthand. This will automatically update
   `package.json`, commit, then create a tag.
4. Push the branch, but not yet the tag.
5. Create a PR to approve the changes.
6. Once approved:
    1. Update the git tag to the new head of the branch, if necessary.
    2. Push the git tag (`git push origin tag v<version>`). Doing so triggers
       the github actions workflow which builds and publishes to npm, and
       creates a draft GH release.
    3. Merge the PR. (Prefer a genuine merge rather than a squash so that
       the tagged commit is included in the history.)
7. Update the release on github and publish.
