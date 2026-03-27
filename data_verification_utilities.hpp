#ifndef IRODS_POLICY_COMPOSITION_DATA_VERIFICATION_UTILITIES_HPP
#define IRODS_POLICY_COMPOSITION_DATA_VERIFICATION_UTILITIES_HPP

#include <irods/rcConnect.h>
#include <string>

namespace irods
{
	bool verify_replica_for_destination_resource(
		rsComm_t* _comm,
		const std::string& _verification_type,
		const std::string& _logical_path,
		const std::string& _source_resource,
		const std::string& _destination_resource);
	void get_object_and_collection_from_path(
		const std::string& _logical_path,
		std::string& _collection_name,
		std::string& _object_name);
	std::string
	compute_checksum_for_resource(rsComm_t* _comm, const std::string& _logical_path, const std::string& _resource_name);

} // namespace irods

#endif // IRODS_POLICY_COMPOSITION_DATA_VERIFICATION_UTILITIES_HPP
