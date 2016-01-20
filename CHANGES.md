# GENI Clearinghouse Release Notes

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
