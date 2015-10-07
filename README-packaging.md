# Building a package for RedHat/CentOS

The geni-ch distribution includes the information needed to build an
rpm package. In order to build the package you must first install
the rpm packaging tools. On CentOS 6 and 7, the tools can be
installed with the following commands:

```
yum install rpm-build rpmdevtools rpmlint
yum groupinstall "Development Tools"
```

As a regular user (not root), set up an rpm build area:

```
rpmdev-setuptree
```

Download the geni-ch tar file. Check for the file on the releases tab at
the [GitHub project page](https://github.com/GENI-NSF/geni-ch).

Once the tar file has been downloaded,
follow these steps to build the package:

```
VERSION=2.2
tar zxf geni-chapi-${VERSION}.tar.gz
mv geni-chapi-${VERSION}.tar.gz "${HOME}"/rpmbuild/SOURCES
mv geni-ch-${VERSION}/geni-chapi.spec "${HOME}"/rpmbuild/SPECS
cd "${HOME}"/rpmbuild/SPECS
rpmbuild -ba geni-chapi.spec
```

This will generate the following files:
 * The rpm: `"${HOME}"/rpmbuild/RPMS/noarch/geni-chapi-2.2-1.el7.noarch.rpm`
 * The source rpm: `"${HOME}"/rpmbuild/SRPMS/geni-chapi-2.2-1.el7.src.rpm`

# Creating a yum repository

Install the `createrepo` tool:

```
yum install createrepo
```

Create a repository directory and move the files into it:

```
mkdir repo
cd repo
mv "${HOME}"/rpmbuild/RPMS/noarch/geni-chapi-2.2-1.el7.noarch.rpm .
mv "${HOME}"/rpmbuild/SRPMS/geni-chapi-2.2-1.el7.src.rpm .
mv "${HOME}"/rpmbuild/SOURCES/geni-chapi-2.2.tar.gz .
mv "${HOME}"/rpmbuild/SPECS/geni-chapi.spec .

```

Generate the repository metadata:

```
createrepo --database .
```

Copy this entire directory to the repository server
(update the host and path as needed):

```
scp -r * repo.example.com:/path/centos/7/os/x86_64
```

Configure yum for the new repository by creating a file
in `/etc/yum.repos.d` named geni.repo with the following
contents (updating the host and path as needed):

```
[geni]
name = GENI software repository
baseurl = http://repo.example.com/path/centos/$releasever/os/$basearch/
```
