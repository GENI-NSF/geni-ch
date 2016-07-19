# GENI Clearinghouse Release Notes

# [Release 2.14](https://github.com/GENI-NSF/geni-ch/milestones/2.14)

## Changes

* Create automated test suite for geni-ch API calls
([#504](https://github.com/GENI-NSF/geni-ch/issues/504))
* Remove InstaGENI FOAM aggregates
([#514](https://github.com/GENI-NSF/geni-ch/issues/514))
* Fix SR get_services_of_type to return the standard code/value/output triple
([#516](https://github.com/GENI-NSF/geni-ch/issues/516))

## Installation Notes

* Delete outdated service registry files _prior_ to installation:

```shell
sudo rm -rf /usr/share/geni-chapi/sr/certs
sudo rm -rf /usr/share/geni-chapi/sr/sql
```

# [Release 2.13](https://github.com/GENI-NSF/geni-ch/milestones/2.13)

## Changes

* Communicate max slice expiration in SA get_version
([#464](https://github.com/GENI-NSF/geni-ch/issues/464))
* Update CentOS install for WSGI
([#508](https://github.com/GENI-NSF/geni-ch/issues/508))
* Updates to install document
([#471](https://github.com/GENI-NSF/geni-ch/issues/471))

## Installation Notes

* None

# [Release 2.12](https://github.com/GENI-NSF/geni-ch/milestones/2.12)

## Changes

* Provide project credentials via SA.get_credentials
([#466](https://github.com/GENI-NSF/geni-ch/issues/466))
* Remove dependency on libabac
([#467](https://github.com/GENI-NSF/geni-ch/issues/467))
* Fix speaks-for attribute in service registry
([#497](https://github.com/GENI-NSF/geni-ch/issues/497))

## Installation Notes

# [Release 2.11.1](https://github.com/GENI-NSF/geni-ch/milestones/2.11.1)

## Changes

* Fix XML-RPC responses
([#492](https://github.com/GENI-NSF/geni-ch/issues/492))

# [Release 2.11](https://github.com/GENI-NSF/geni-ch/milestones/2.11)

## Changes

* Remove PGCH service
  ([#474](https://github.com/GENI-NSF/geni-ch/issues/474))
* Restrict project names a little bit more
  ([#480](https://github.com/GENI-NSF/geni-ch/issues/480))

## Installation Notes

  * Remove obsolete installed files if they exist

      ```
      sudo rm -f /usr/share/geni-ch/chapi/AMsoil/src/plugins/pgch
      sudo rm -rf /usr/share/geni-ch/chapi/chapi/plugins/pgch
      sudo rm -f /usr/share/geni-ch/chapi/chapi/tools/pgch_testall.sh
      sudo rm -f /usr/share/geni-ch/chapi/chapi/tools/pgch_client.py
      sudo rm -f /usr/share/geni-ch/chapi/chapi/linkamsoil.sh
      sudo rm -f /etc/geni-chapi/chapi-centos.ini
      sudo rm -f /usr/share/geni-ch/chapi/chapi/tools/install_ch
      sudo rm -f /usr/share/geni-ch/chapi/chapi/tools/install_chapi
      sudo rm -f /usr/share/geni-ch/chapi/chapi/tools/install_db
      sudo rm -f /usr/share/geni-ch/chapi/chapi/tools/testall.sh
      ```

# [Release 2.10](https://github.com/GENI-NSF/geni-ch/milestones/2.10)

* Update CentOS installation docs
  ([#463](https://github.com/GENI-NSF/geni-ch/issues/463))
* Drop chapi from make sync
  ([#468](https://github.com/GENI-NSF/geni-ch/issues/468))
* Add aggregate configurations for future install
  ([#469](https://github.com/GENI-NSF/geni-ch/issues/469))

# [Release 2.9](https://github.com/GENI-NSF/geni-ch/milestones/2.9)

* Allow KEY_TYPE as an argument to MA.create_key()
  ([#458](https://github.com/GENI-NSF/geni-ch/issues/458))

# [Release 2.8](https://github.com/GENI-NSF/geni-ch/milestones/2.8)

* Fix removing lead from project error finding an alternate lead.
  ([#451](https://github.com/GENI-NSF/geni-ch/issues/451))
* Reduce the use of AMsoil config plug-in at runtime
  ([#454](https://github.com/GENI-NSF/geni-ch/issues/454))

# [Release 2.7](https://github.com/GENI-NSF/geni-ch/milestones/2.7)

* Stop CC'ing on expiring certificate email
  ([#441](https://github.com/GENI-NSF/geni-ch/issues/441))
* Allow SLICE_PROJECT_URN to designate project subject
  ([#442](https://github.com/GENI-NSF/geni-ch/issues/442))
* Change text of project lead email
  ([#446](https://github.com/GENI-NSF/geni-ch/issues/446))

# [Release 2.6](https://github.com/GENI-NSF/geni-ch/milestones/2.6)

* Skip SQL in clause when collection is empty
  ([#427](https://github.com/GENI-NSF/geni-ch/issues/427))
* Add iRODS SR scripts
  ([#436](https://github.com/GENI-NSF/geni-ch/issues/436))
* Move iRODS certs to clearinghouse
  ([#437](https://github.com/GENI-NSF/geni-ch/issues/437))
* Add VTS aggregates to service registry
  ([#438](https://github.com/GENI-NSF/geni-ch/issues/438))

# [Release 2.5](https://github.com/GENI-NSF/geni-ch/milestones/2.5)

* Return short name from SR
  ([#430](https://github.com/GENI-NSF/geni-ch/issues/430))
* Merge transition related changes
  ([#432](https://github.com/GENI-NSF/geni-ch/issues/432))

# [Release 2.4](https://github.com/GENI-NSF/geni-ch/milestones/2.4)

* Migrate management scripts from geni-portal to geni-ch
  ([#101](https://github.com/GENI-NSF/geni-ch/issues/101))
* Return dates as strings from SA create
  ([#397](https://github.com/GENI-NSF/geni-ch/issues/397))
* Raise not implemented error for delete slice and delete project
  ([#398](https://github.com/GENI-NSF/geni-ch/issues/398))
* Stop generating fake project email addresses
  ([#399](https://github.com/GENI-NSF/geni-ch/issues/399))
* Ensure fields exist before updating
  ([#411](https://github.com/GENI-NSF/geni-ch/issues/411))
* Ensure `now < slice_expiration < max_expiration`
  ([#413](https://github.com/GENI-NSF/geni-ch/issues/413))
* Validate project expiration dates
  ([#419](https://github.com/GENI-NSF/geni-ch/issues/419))
* Set default values for slice and project creation
  ([#414](https://github.com/GENI-NSF/geni-ch/issues/414))
* Return last_name to monitoring when present
  ([#424](https://github.com/GENI-NSF/geni-ch/issues/424))

# [Release 2.3](https://github.com/GENI-NSF/geni-ch/milestones/2.3)

 * Add geni-revoke-member-certificate man page
   ([#404](https://github.com/GENI-NSF/geni-ch/issues/404))

# [Release 2.2](https://github.com/GENI-NSF/geni-ch/milestones/2.2)

 * Migrate SR certs from geni-portal to geni-ch
   ([#102](https://github.com/GENI-NSF/geni-ch/issues/102))

# [Release 2.1.1](https://github.com/GENI-NSF/geni-ch/milestones/2.1.1)

 * Fix a bug in lookup_project_attributes where the PROJECT_UID option was
   required to be a list. Allow it to be a single UID.
   ([#400](https://github.com/GENI-NSF/geni-ch/issues/400))

# [Release 2.1](https://github.com/GENI-NSF/geni-ch/milestones/2.1)

 * Migrate CH tables from geni-portal to geni-ch
   ([#103](https://github.com/GENI-NSF/geni-ch/issues/103))
 * Support lists of project_ids in option for lookup_project_attributes
   ([#391](https://github.com/GENI-NSF/geni-ch/issues/391))
 * Return most recent slice from SA.lookup and SA.lookup_slices
   ([#393](https://github.com/GENI-NSF/geni-ch/issues/393))
 * Allow JSON booleans for boolean type arguments to API calls
   ([#394](https://github.com/GENI-NSF/geni-ch/issues/394))

# [Release 2.0](https://github.com/GENI-NSF/geni-ch/milestones/2.0)

 * Add procedure to add new aggregate
   ([#383](https://github.com/GENI-NSF/geni-ch/issues/383))
 * Minor tweaks to `portal_stats.sql`
