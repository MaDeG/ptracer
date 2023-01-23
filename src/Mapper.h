/* 
 * File:   Mapper.h
 * Author: Matteo De Giorgi
 *
 * Created on 18 November 2016, 10:53
 */

#ifndef PTRACER_MAPPER_H
#define PTRACER_MAPPER_H
#include <boost/bimap.hpp>
#include <fstream>
#include "dto/ProcessSyscallEntryDto.h"
#include "Tracer.h"

//TODO: Is a bimap really necessary? When is it necessary to retrieve the id given a ProcessSyscallEntry?
typedef boost::bimap<unsigned int, ProcessSyscallEntryDTO> AssociationType;

class Mapper {
public:
  static const std::string FIELD_SEPARATOR;
  static const std::string SECTION_START;
  static const std::string SECTION_END;
  static const int NOT_FOUND;
  Mapper(const std::string& storeFile);
  ~Mapper();
  unsigned int insert(const std::shared_ptr<ProcessSyscallEntry>& state);
  unsigned int find(const std::shared_ptr<ProcessSyscallEntry>& state) const;
  std::shared_ptr<ProcessSyscallEntryDTO> find(const std::string& executableName, int associationId) const;
  bool save();
  unsigned int getSize() const;
	std::string getAssociationsFile() const;
  
protected:
  bool import();
  
private:
  const std::string storeFile;
  std::ifstream storeIn;
  std::ofstream storeOut;
  std::map<std::string, AssociationType> associations;
};

#endif /* PTRACER_MAPPER_H */