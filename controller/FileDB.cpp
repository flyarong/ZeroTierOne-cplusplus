/*
 * ZeroTier One - Network Virtualization Everywhere
 * Copyright (C) 2011-2019  ZeroTier, Inc.  https://www.zerotier.com/
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 *
 * --
 *
 * You can be released from the requirements of the license by purchasing
 * a commercial license. Buying such a license is mandatory as soon as you
 * develop commercial closed-source software that incorporates or links
 * directly against ZeroTier software without disclosing the source code
 * of your own application.
 */

#include "FileDB.hpp"

namespace ZeroTier
{

FileDB::FileDB(EmbeddedNetworkController *const nc,const Identity &myId,const char *path) :
	DB(nc,myId,path),
	_networksPath(_path + ZT_PATH_SEPARATOR_S + "network"),
	_tracePath(_path + ZT_PATH_SEPARATOR_S + "trace")
{
	OSUtils::mkdir(_path.c_str());
	OSUtils::lockDownFile(_path.c_str(),true);
	OSUtils::mkdir(_networksPath.c_str());
	OSUtils::mkdir(_tracePath.c_str());

	std::vector<std::string> networks(OSUtils::listDirectory(_networksPath.c_str(),false));
	std::string buf;
	for(auto n=networks.begin();n!=networks.end();++n) {
		buf.clear();
		if ((n->length() == 21)&&(OSUtils::readFile((_networksPath + ZT_PATH_SEPARATOR_S + *n).c_str(),buf))) {
			try {
				nlohmann::json network(OSUtils::jsonParse(buf));
				const std::string nwids = network["id"];
				if (nwids.length() == 16) {
					nlohmann::json nullJson;
					_networkChanged(nullJson,network,false);
					std::string membersPath(_networksPath + ZT_PATH_SEPARATOR_S + nwids + ZT_PATH_SEPARATOR_S "member");
					std::vector<std::string> members(OSUtils::listDirectory(membersPath.c_str(),false));
					for(auto m=members.begin();m!=members.end();++m) {
						buf.clear();
						if ((m->length() == 15)&&(OSUtils::readFile((membersPath + ZT_PATH_SEPARATOR_S + *m).c_str(),buf))) {
							try {
								nlohmann::json member(OSUtils::jsonParse(buf));
								const std::string addrs = member["id"];
								if (addrs.length() == 10) {
									nlohmann::json nullJson2;
									_memberChanged(nullJson2,member,false);
								}
							} catch ( ... ) {}
						}
					}
				}
			} catch ( ... ) {}
		}
	}
}

FileDB::~FileDB() {}

bool FileDB::waitForReady() { return true; }
bool FileDB::isReady() { return true; }

void FileDB::save(nlohmann::json *orig,nlohmann::json &record)
{
	try {
		if (orig) {
			if (*orig != record) {
				record["revision"] = OSUtils::jsonInt(record["revision"],0ULL) + 1;
			}
		} else {
			record["revision"] = 1;
		}

		const std::string objtype = record["objtype"];
		if (objtype == "network") {
			const uint64_t nwid = OSUtils::jsonIntHex(record["id"],0ULL);
			if (nwid) {
				nlohmann::json old;
				get(nwid,old);

				if ((!old.is_object())||(old != record)) {
					char npath[4096];
					OSUtils::ztsnprintf(npath,sizeof(npath),"%s" ZT_PATH_SEPARATOR_S "%.16llx.json",_networksPath.c_str(),nwid);
					if (!OSUtils::writeFile(npath,OSUtils::jsonDump(record,-1)))
						fprintf(stderr,"WARNING: controller unable to write to path: %s" ZT_EOL_S,npath);
					_networkChanged(old,record,true);
				}
			}
		} else if (objtype == "member") {
			const uint64_t id = OSUtils::jsonIntHex(record["id"],0ULL);
			const uint64_t nwid = OSUtils::jsonIntHex(record["nwid"],0ULL);
			if ((id)&&(nwid)) {
				nlohmann::json network,old;
				get(nwid,network,id,old);

				if ((!old.is_object())||(old != record)) {
					char pathBase[4096],mpath[4096],npath[4096];
					OSUtils::ztsnprintf(pathBase,sizeof(pathBase),"%s" ZT_PATH_SEPARATOR_S "%.16llx" ZT_PATH_SEPARATOR_S "member",_networksPath.c_str(),(unsigned long long)nwid);
					OSUtils::ztsnprintf(mpath,sizeof(mpath),"%s" ZT_PATH_SEPARATOR_S "%.10llx.json",pathBase,(unsigned long long)id);
					if (!OSUtils::writeFile(mpath,OSUtils::jsonDump(record,-1))) {
						OSUtils::ztsnprintf(npath,sizeof(npath),"%s" ZT_PATH_SEPARATOR_S "%.16llx",_networksPath.c_str(),(unsigned long long)nwid);
						OSUtils::mkdir(npath);
						OSUtils::mkdir(pathBase);
						if (!OSUtils::writeFile(mpath,OSUtils::jsonDump(record,-1)))
							fprintf(stderr,"WARNING: controller unable to write to path: %s" ZT_EOL_S,mpath);
					}
					_memberChanged(old,record,true);
				}
			}
		} else if (objtype == "trace") {
			const std::string id = record["id"];
			if (id.length() > 0) {
				char tpath[4096];
				OSUtils::ztsnprintf(tpath,sizeof(tpath),"%s" ZT_PATH_SEPARATOR_S "%s.json",_tracePath.c_str(),id.c_str());
				OSUtils::writeFile(tpath,OSUtils::jsonDump(record,-1));
			}
		}
	} catch ( ... ) {} // drop invalid records missing fields
}

void FileDB::eraseNetwork(const uint64_t networkId)
{
	nlohmann::json network,nullJson;
	get(networkId,network);
	char p[4096];
	OSUtils::ztsnprintf(p,sizeof(p),"%s" ZT_PATH_SEPARATOR_S "%.16llx.json",_networksPath.c_str(),networkId);
	OSUtils::rm(p);
	_networkChanged(network,nullJson,true);
}

void FileDB::eraseMember(const uint64_t networkId,const uint64_t memberId)
{
	nlohmann::json member,nullJson;
	get(memberId,member);
	char p[4096];
	OSUtils::ztsnprintf(p,sizeof(p),"%s" ZT_PATH_SEPARATOR_S "%.16llx" ZT_PATH_SEPARATOR_S "member" ZT_PATH_SEPARATOR_S "%.10llx.json",_networksPath.c_str(),networkId,memberId);
	OSUtils::rm(p);
	_memberChanged(member,nullJson,true);
}

void FileDB::nodeIsOnline(const uint64_t networkId,const uint64_t memberId,const InetAddress &physicalAddress)
{
	// Nothing to do here right now in the filesystem store mode since we can just get this from the peer list
}

} // namespace ZeroTier
