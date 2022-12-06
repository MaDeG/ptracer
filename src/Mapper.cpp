/* 
 * File:   Mapper.cpp
 * Author: Matteo De Giorgi
 * 
 * Created on 18 November 2016, 10:53
 */

#include <iostream>
#include <boost/algorithm/string.hpp>
#include <boost/lexical_cast.hpp>
#include "Mapper.h"
#include "Tracer.h"

//TODO: Use a more modern serialization and deserialization approach

using namespace std;

// Separator that will be used to separate Keys and values in the serialised representation
const string Mapper::FIELD_SEPARATOR = "\x1D";
// Dictates the beginning of a section, it must be followed by the executable name which the following associations refers to
const string Mapper::SECTION_START = "Section begin: ";
// Dictates the end of a section, it must always be present at least once in a association store file
const string Mapper::SECTION_END = "Section end";
// Returned when a state is not found
const int Mapper::NOT_FOUND = -1;

/**
 * Construct a new Mapper that will store associations between state numbers (progressive starting
 * from 1) and ProcessStates.
 * 
 * @param store The file path where the Mapper serialised version will be stored.
 */
Mapper::Mapper(const string& storeFile) : storeFile(storeFile) {
  try {
    this->storeIn.open(this->storeFile, ios::in);
    if (this->storeIn.good()) {
      if (!this->import()) {
        cout << "Error occurred while trying to import previously stored associations, start from scratch" << endl;
        this->associations.clear();
      }
    } else {
      cout << "Previously stored associations not found in " << this->storeFile << endl;
      this->storeOut.open(this->storeFile, ios::out);
      this->storeIn.open(this->storeFile, ios::in);
    }
  } catch (ios_base::failure& e) {
    cerr << "Error while trying to open " << this->storeFile << ": " << e.what() << endl;
    errno = 0;
  }
}

/**
 * Make sure that at the object destruction the store file is safe.
 */
Mapper::~Mapper() {
  this->storeOut.flush();
  this->storeOut.close();
  this->storeIn.close();
}

/**
 * Used to import old associations if this is not the first learning.
 * It assumes the file line format: "(association_number)(Mapper::FIELD_SEPARATOR)(serialized ProcessState)".
 * Called by the constructor in order to import an initial set of associations.
 * 
 * @return True if there were no I/O errors nor format problems.
 */
bool Mapper::import() {
  string cur_line;
  string executableName;
  int associationId;
  vector<string> tokens;
  assert(this->storeIn.is_open());
  while (getline(this->storeIn, cur_line)) {
	  // Expects a section start
    if (cur_line.find(Mapper::SECTION_START) >= cur_line.size()) {
      cerr << "Cannot find a section begin" << endl;
      return false;
    }
	  executableName = cur_line.substr(cur_line.find(Mapper::SECTION_START) + Mapper::SECTION_START.size(), cur_line.size());
    assert(!executableName.empty());
    assert(executableName.find(Mapper::SECTION_START) >= executableName.size());
    cout << "Importing associations for executable: " << executableName << endl;
    while (getline(this->storeIn, cur_line) && cur_line.find(Mapper::SECTION_END.c_str(), 0, Mapper::SECTION_END.size()) >= cur_line.size()) {
      tokens.clear();
      boost::split(tokens, cur_line, boost::is_any_of(Mapper::FIELD_SEPARATOR));
      if (tokens.size() != 2) {
        cerr << "Missing association value for key number in line " << cur_line << endl;
        return false;
      }
	    associationId = boost::lexical_cast<int>(tokens.at(0).c_str());
      if (associationId < 1) {
        cerr << "Found an invalid association number: " << tokens.at(0) << endl;
        return false;
      }
      try {
	      auto* state = new ProcessSyscallEntryDTO(tokens.at(1), executableName);
        if (!this->associations[executableName].insert(AssociationType::value_type((unsigned int) associationId, *state)).second) {
          cerr << "Impossible to import the association number " << associationId << endl;
          return false;
        }
        //cout << "Successfully imported association number " << associationId << ":" << endl;
      } catch (runtime_error& e) {
        cout << e.what() << endl;
        return false;
      }
    }
    // Section end acquisition
    if (cur_line != Mapper::SECTION_END) {
      cerr << "Impossible to find the executable name " << executableName << " section end declaration" << endl;
      return false;
    }
    cout << "Imported " << this->associations[executableName].size() << " associations for " << executableName << endl;
  }
  return true;
}

/**
 * It saves all the stored associations in Mapper::store_out.
 * Every association will be stored in the format: "(association_number)(Mapper::FIELD_SEPARATOR)(serialized ProcessState)".
 * 
 * @return True if there were no I/O errors nor format problems.
 */
bool Mapper::save() {
  if (!this->storeOut.is_open()) {
    try {
      this->storeOut.open(this->storeFile, ios::out);
    } catch (ios_base::failure& e) {
      cerr << "Error while trying to open " << this->storeFile << " in write mode: " << e.what() << endl;
      errno = 0;
      return false;
    }
  }
  cout << "Saving associations in " << this->storeFile << endl;
  for (auto& executableIt : this->associations) {
    cout << "Saving associations for the executable " << executableIt.first << "..." << endl;
    this->storeOut << Mapper::SECTION_START << executableIt.first << endl;
    for (auto& i : this->associations[executableIt.first].left) {
      this->storeOut << i.first << Mapper::FIELD_SEPARATOR << i.second.serialize();
    }
    this->storeOut << Mapper::SECTION_END << endl;
    this->storeOut.flush();
    cout << "For the executable " << executableIt.first << " " << this->associations[executableIt.first].size() << " associations has been saved" << endl;
  }
  if (!this->storeOut.good()) {
    cerr << "Error occurred while writing associations in " << this->storeFile << endl;
    return false;
  }
  return true;
}

/**
 * Insert a new ProcessSyscallDTO in the associations map.
 * If that state is already present no action will be performed.
 * 
 * @param state The ProcessSyscallEntry that will be added to the associations map.
 * @return The association number related to the provided state or a negative number if fails.
 */
unsigned int Mapper::insert(const shared_ptr<ProcessSyscallEntry>& state) {
  unsigned int nextId = this->getSize() + 1;
	ProcessSyscallEntryDTO stateDTO(*state);
	auto it = this->associations[state->getExecutableName()].right.insert(AssociationType::right_value_type(stateDTO, nextId));
  return it.first->get_left();
}

/**
 * It looks for a ProcessState in the association map and returns its key.
 * 
 * @param state The ProcessState that will be searched.
 * @return Returns: The association number (or map key) of the specified ProcessState.
 *                  Mapper::NOT_FOUND If the given state has not been found.
 */
unsigned int Mapper::find(const shared_ptr<ProcessSyscallEntry>& state) const {
	auto it = this->associations.find(state->getExecutableName());
  if (it == this->associations.end()) {
    return Mapper::NOT_FOUND;
  }
	ProcessSyscallEntryDTO stateDTO(*state);
  AssociationType::right_map::const_iterator result = it->second.right.find(stateDTO);
  return result != it->second.right.end() ? (int) result->second : Mapper::NOT_FOUND;
}

/**
 * It looks for an association number and return its associated ProcessSyscallEntry.
 * 
 * @param executableName    The executable name which association number is related to.
 * @param associationId The association number that will be searched.
 * @return The ProcessState associated with the specified key, nullptr if it does not exist.
 */
shared_ptr<ProcessSyscallEntryDTO> Mapper::find(const string& executableName, int associationId) const {
	auto it = this->associations.find(executableName);
  if (it == this->associations.end()) {
    return nullptr;
  }
  AssociationType::left_map::const_iterator result = it->second.left.find(associationId);
  return result != it->second.left.end() ? make_shared<ProcessSyscallEntryDTO>(result->second) : nullptr;
}

/**
 * It returns the number of associations inside the association map.
 * 
 * @return The association map size.
 */
unsigned int Mapper::getSize() const {
  unsigned int total_size = 0;
  for (const auto& i : this->associations) {
    total_size += (unsigned int) i.second.size();
  }
  return total_size;
}

std::string Mapper::getAssociationsFile() const {
	return this->storeFile;
}