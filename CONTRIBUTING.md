# Contributing to geni-tools

The GENI-NSF repositories are very much a community driven effort, and
your contributions are critical. A big thank you to all our contributors!

## Mailing Lists
 * GENI Portal and Clearinghouse users may raise issues or get announcements on the general [GENI Users mailing list](https://groups.google.com/forum/#!forum/geni-users).
 * GENI developers discuss general GENI development on dev@geni.net. Subscribe here: http://lists.geni.net/mailman/listinfo/dev.

## General Guidelines
 - GENI-NSF projects follow the general [GitHub open source project guidelines](https://guides.github.com/activities/contributing-to-open-source/#contributing).
 - [Create a GitHub Issue](#reporting-issues) for any bug, feature, or enhancement you find or intend to address.
 - Submit enhancements or bug fixes using pull requests (see the [sample workflow below](#sample-contribution-workflow)).
 - GENI-NSF projects use the branching model found at
 http://nvie.com/posts/a-successful-git-branching-model/
  - All work happens in issue-specific branches off of the `develop`
  branch.
   - For example, a branch for Issue 1234 might be named `tkt1234-my-feature`.
 - Note that all GENI-NSF code is released under the [GENI Public License](LICENSE.txt) and should include that license.

## Reporting Issues ##
 - Check [existing issues](https://github.com/GENI-NSF/geni-ch/issues) first to see if the issue has already been reported.
 - Review the general [GitHub guidlines on isssues](https://guides.github.com/features/issues/).
 - Give specific examples, sample outputs, etc
 - Do not include any passwords, private keys, your `omni.bundle`, or any information you don't want public.
 - When reporting issues, please include screen shots (simply drag them in), a description of what you did, any request RSpec, etc.
 - To attach your test case RSpecs or other large output, upload the file to some web server and provide a pointer. For example, to use Gist:
  - Copy & paste your log/patch/file attachment to http://gist.github.com/, hit the `Create Public` button and link to it from your issue by copying & pasting its URL.

## Getting the Source
GENI Clearinghouse source code is available on [GitHub](https://github.com/GENI-NSF/geni-ch).

## Sample Contribution Workflow ##
 1. [Report the issue](#reporting-issues) or check issue comments for a suggested solution.
 2. Create an issue-specific branch off of the `develop` branch in your [fork of the repository](http://guides.github.com/activities/forking/).
  - Per the [branching model](http://nvie.com/posts/a-successful-git-branching-model/)
  - E.G. `git checkout develop`, `git pull origin develop`, and then `git checkout -b tkt1234-my-feature`
 3. Develop your fix.
  - Follow the [code guidelines below](#code-style).
  - Reference the appropriate issue numbers in your commit messages.
  - Include the [GENI Public License](LICENSE.txt) and a copyright notice in any new source files.
  - All changes should be listed in the [CHANGES](CHANGES) file, with an issue number.
 4. Test your fix
 5. [Pull in any new changes](https://help.github.com/articles/syncing-a-fork) from the main repository ('upstream' repository).
 6. [Submit a pull request](https://help.github.com/articles/using-pull-requests/) against the `develop` branch of the project repository.
 - In your pull request description, note what issue(s) your pull request addresses.

## Code Style ##
 - Include the [GENI Public License](LICENSE.txt) as a comment at the top of all source files.
 - Document all files and key classes and methods.
 - Name classes, methods, arguments and variables to describe their use.
 - Use 4 space indents.
 - Follow the [Python Style Guide](https://www.python.org/dev/peps/pep-0008/).

_Thank you for your contributions!_
