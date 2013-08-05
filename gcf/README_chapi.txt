Mapping of OMNI functions to CHAPI:

get_ch_version
	get_version on the CH

listaggregates
	get_aggregates on CH

createslice <slicename>
	create_slice on SA

getslicecred <slicename>
	lookup_slices (only this slice, only the slice credential) on SA

renewslice <slicename> <new expiration time in UTC>
	update_slice on SA

deleteslice <slicename>
	CAN'T DELETE A SLICE

listslices [optional: username] [Alias for listmyslices]
listmyslices [optional: username]
	lookup_slices on SA

getusercred
	lookup_public_member_info on MA [specifically for User Cred]

print_slice_expiration <slicename> 
	(lookup_slices on SA)
	OMNI handles this with lookup_slice calls
