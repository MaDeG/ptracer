#include <amore++/nondeterministic_finite_automaton.h>
#include <amore++/finite_automaton.h>
#include <amore_alf_glue.h>
#include <libalf/basic_string.h>
#include <memory>
#include <string>
#include <streambuf>
#include "Authorizer.h"
#include "Mapper.h"
#include "Launcher.h"
#include "ProcessSyscallExit.h"
#include "ProcessTermination.h"

using namespace std;

// Returned when a ProcessState is authorised
const int Authorizer::AUTHORISED = 0;
// Returned when a ProcessState is NOT authorised
const int Authorizer::NOT_AUTHORISED = -1;
// Returned when a ProcessState is not a final state as it should be
const int Authorizer::NOT_FINAL = -2;

/**
 * Create a new Authorizer specifying used files path.
 * This object assumes that TracingManager has already been initialised.
 * 
 * @param graphPath The path where a serialised NFA is expected, if it does not exist will be created.
 * @param associationsPath The associations file path, if it does not exist will be created.
 * @param learning   Specify if the Authorizer will act in learning mode or not.
 */
Authorizer::Authorizer(const string graphPath, const string associationsPath, const bool learning) : graphPath    (graphPath),
																												                                             learning     (learning),
																												                                             associations (associationsPath) {
  if (!this->importAutomaton()) {
    ERROR("Initial automata not imported");
    this->automata = nullptr;
  }
	if (!this->learning && this->automata == nullptr) {
		ERROR("A valid automaton is needed in enforce mode");
		exit(1);
	}
}

void Authorizer::process(std::shared_ptr<ProcessNotification> syscall) {
	// If the Syscall is NOT authorized, and we are NOT allowed to continue
	int returnValue = this->isAuthorized(syscall);
	if (returnValue == Authorizer::NOT_AUTHORISED && !this->handleUnauthorised(syscall)) {
		return;
	}
	if (returnValue == Authorizer::NOT_FINAL && !this->handleNonFinal(syscall)) {
		return;
	}
	shared_ptr<ProcessSyscallEntry> entry = dynamic_pointer_cast<ProcessSyscallEntry>(syscall);
	if (entry != nullptr) {
		if (!TracingManager::authorize(entry)) {
			cerr << "Error occurred while trying to authorize a system call for SPID " << syscall->getSpid() << endl;
		}
	}
}

void Authorizer::terminate() {
	if (!this->learning) {
		this->checkFinalStates();
	} else {
		this->buildAutomata();
	}
	if(!this->save()) {
		ERROR("Error occurred while saving the automata in " + this->graphPath);
	}
	if (!this->associations.save()) {
		ERROR("Error occurred while saving the associations");
	}
}

/**
 * Create a DOT representation of the NFA.
 * 
 * @param filePath The output file where the DOT representation will be stored.
 * @return True if the DOT representation generation was successful, False otherwise.
 */
bool Authorizer::dotOutput(const string& filePath) const {
  ofstream dotFile;
  if (this->automata == nullptr) {
    cerr << "No automaton has been generated" << endl;
    return false;
  }
  try {
    dotFile.open(filePath, ios::out);
  } catch (ios_base::failure& e) {
    ERROR("Impossible to open " + filePath + " in write mode: " + e.what());
    return false;
  }
  cout << "Generation of automaton DOT format..." << endl;
  string dotString = this->automata->visualize();
  if (dotString.empty()) {
    ERROR("Error in the dot format generation");
    return false;
  }
  cout << "Automaton DOT format successfully generated" << endl;
  // The last visible character is a ';' but it is not part of the dot format
  if (dotString.at(dotString.size() - 2) == ';') {
    dotString.erase(dotString.end() - 2);
  }
  cout << "Writing DOT output file..." << endl;
  dotFile << dotString;
  dotFile.flush();
  if (!dotFile.good()) {
    ERROR("Error occurred during DOT file write");
    dotFile.close();
    return false;
  }
  dotFile.close();
  cout << "Automaton in DOT format saved in " << filePath << endl;
  return true;
}

Authorizer::operator string() const {
	stringstream result;
	result << "Learning: " << (this->learning ? "true" : "false") << endl;
	result << "NFA Path: " << this->graphPath << endl;
	result << "Associations Path: " << this->associations.getAssociationsFile() << endl;
	return result.str();
}

// TODO: Automata should be build on the fly, it should not be necessary to store all the states

/**
 * It builds a new NFA automata starting from the input automata (taken from a previous execution), if it exists.
 * This is called at the end of the tracee execution.
 */
void Authorizer::buildAutomata() {
  // Set of initial and final states
  set<int> initials, finals;
  int stateOld, stateNew;
  // Map containing the last inserted state for every traced thread
  map<pid_t, map<pid_t, int>> lastStates;
  // Map containing transitions in the form < origin, < transition_label, { destination_nodes } > >
  map<int, map<int, set<int>>> transitions, preTransitions;
  shared_ptr<ProcessSyscallEntry> syscall;
  shared_ptr<ProcessTermination> termination;
  cout << "Building the NFA automata..." << endl;
  if (this->automata != nullptr) {
    this->automata->get_transition_maps(preTransitions, transitions);
    initials = this->automata->get_initial_states();
    finals = this->automata->get_final_states();
  } else {
    this->automata = make_unique<amore::nondeterministic_finite_automaton>();
		// State 0 does not correspond to any Syscall
    initials = { 0 };
    stateOld = 0;
  }
	lastStates[(*this->processStates.begin())->getPid()][(*this->processStates.begin())->getSpid()] = 0;
  assert(initials.size() == 1);
  for (const shared_ptr<ProcessNotification>& i : this->processStates) {
		if (dynamic_pointer_cast<ProcessSyscallExit>(i)) {
			// Not interested in exit notifications
			continue;
		}
	  termination = dynamic_pointer_cast<ProcessTermination>(i);
    if (termination) {
      finals.insert(lastStates[termination->getPid()][termination->getSpid()]);
      continue;
    }
		// Handling of ProcessSyscallEntry
		syscall = dynamic_pointer_cast<ProcessSyscallEntry>(i);
    assert(lastStates.find(syscall->getPid()) != lastStates.end());
    assert(lastStates[syscall->getPid()].find(syscall->getSpid()) != lastStates[syscall->getPid()].end());
    stateOld = lastStates[syscall->getPid()][syscall->getSpid()];
    // Insert a new Process State to the Mapper file
    stateNew = this->associations.insert(syscall);
    if (stateNew < 0) {
      ERROR("Error occurred during automaton transitions generation!");
      break;
    }
    transitions[stateOld][stateNew] = { stateNew };
    // If this is a clone syscall -> bifurcate the graph
    if (syscall->getChildPid() > 0) {
      assert(syscall->getChildPid() > 0 && syscall->getChildPid() < Tracer::MAX_PID);
      assert(syscall->getReturnValue() > 0 && syscall->getReturnValue() < Tracer::MAX_PID);
      // A clone return value contains the newly created thread or process
      lastStates[syscall->getChildPid()][(pid_t) syscall->getReturnValue()] = stateNew;
    }
	  lastStates[syscall->getPid()][syscall->getSpid()] = stateNew;
  }
  // In case of an unexpected termination we still want to set every last state as final
  for (const auto& pid_it : lastStates) {
    for (const auto& spid_it : pid_it.second) {
      finals.insert(spid_it.second);
    }
  }
  if (this->automata->construct(false,
                                (int) this->associations.getSize() + 1,
                                (int) this->associations.getSize() + 1,
                                initials,
                                finals,
                                transitions)) {
    //this->automaton->determinize();
    //this->automaton->minimize();
    cout << "Automaton construction finished" << endl;
		cout << "Number of states: " << this->automata->get_alphabet_size() << endl;
		// TODO: Reimplement the NFA library, DOT generation is very slow and this is a horrible way of finding the total number of transactions
		int transitionNumber = 0;
	  for (const auto& item : transitions) {
		  for (const auto& item : item.second) {
				transitionNumber += item.second.size();
			}
		}
	  cout << "Number of transitions: " << transitionNumber << endl;
		cout << "Final states: " << finals.size() << endl;
    if (!this->save()) {
      ERROR("Error occurred while saving the automata in " + this->graphPath);
    }
  } else {
    ERROR("Impossible to create the automaton");
  }
}

/**
 * It saves the NFA automaton in Authorizer::automaton in the path specified in Authorizer::graphPath.
 * 
 * @return True if the automaton was successfully written, False otherwise.
 */
bool Authorizer::save() {
  ofstream automaton_file;
  cout << "Saving automaton..." << endl;
  try {
    automaton_file.open(this->graphPath, ios::out);
  } catch (ios_base::failure& e) {
    ERROR("Impossible to open " + this->graphPath + " in write/binary mode: " + e.what());
    return false;
  }
  basic_string<int32_t> aut_serialized = this->automata->serialize();
  for (int32_t i : aut_serialized) {
    automaton_file.write((char*) &i, sizeof (i));
  }
  automaton_file.flush();
  if (!automaton_file.good()) {
    ERROR("Error occurred while writing the automaton in " + this->graphPath);
    automaton_file.close();
    return false;
  }
  automaton_file.close();
  cout << "Automaton saved in " << this->graphPath << endl;
  return true;
}

/**
 * Used to add a new automaton transition in such a case where the user decides to add a new allowed
 * ProcessState when we are in enforce mode.
 * 
 * @param state The new state that will be authorised.
 * @return True if the new state has been successfully added, False otherwise.
 */
bool Authorizer::addTransition(shared_ptr<ProcessSyscallEntry> state) {
  int label;
  bool new_state = false;
  assert(this->automata != nullptr);
  map< int, map<int, set<int> > > pre_transitions, transitions;
  this->automata->get_transition_maps(pre_transitions, transitions);  // TODO: Very time consuming operation, shall be optimized
  new_state = this->associations.find(state) == Mapper::NOT_FOUND;
  label = this->associations.insert(state);
  for (const int& i : this->currentStates[state->getSpid()]) {
    transitions[i][label] = { label };
    cout << "Added a new transition from " << i << " to " << label << endl;
  }
  this->currentStates[state->getSpid()] = { label };
  set<int> initial_states = this->automata->get_initial_states();
  set<int> final_states = this->automata->get_final_states();
  // Rebuild the automata
  if (!this->automata->construct(false,
                                 (int) this->automata->get_alphabet_size() + (new_state ? 1 : 0),
                                 (int) this->automata->get_state_count() + (new_state ? 1 : 0),
                                 initial_states,
                                 final_states,
                                 transitions)) {
    ERROR("Impossible to build a new automaton after the new transition insertion");
    return false;
  }
  return true;
}

/**
 * Called by the constructor in order to build an initial automata that will be expanded with 
 * the new trasitions learned or if we are in enforce mode it will be used to check the program
 * behaviour looking for discrepancies.
 * 
 * @return True if the automata import was successful otherwise print an error and return False
 */
bool Authorizer::importAutomaton() {
  assert(this->graphPath.size() > 0);
  ifstream aut_file;
  cout << "Importing the specified graph..." << endl;
  try {
    aut_file.open(this->graphPath, ios::in | ios::binary);
  } catch (ios_base::failure &e) {
    ERROR("Impossible to open input graph file " + this->graphPath + ": " + e.what());
    return false;
  }
	if(aut_file.fail()) {
		ERROR("Input graph file does not exist, skipping import");
		return false;
	}
  basic_string<int32_t> aut_string;
  int32_t t;
  while (aut_file.good()) {
    aut_file.read((char*) &t, sizeof (t));
    aut_string += t;
  }
  basic_string<int32_t>::const_iterator begin = aut_string.begin();
  basic_string<int32_t>::const_iterator end = aut_string.end();
  this->automata = std::make_unique<amore::nondeterministic_finite_automaton>();
  if (this->automata->deserialize(begin, end)) {
    aut_file.close();
    cout << "Automaton successfully imported from " << this->graphPath << endl;
    return true;
  } else {
    ERROR("Error while trying to import the graph from " + this->graphPath);
    aut_file.close();
    return false;
  }
}

/**
 * Checks if a ProcessState is allowed or not.
 * 
 * @param state The ProcessNotification that will be tested.
 * @return Returns: Authorizer::AUTHORISED If state is authorised to proceed.
 *                  Authorizer::NOT_AUTHORISED If state is not authorised to proceed.
 *                  Authorizer::NOT_FINAL If this state is not final as it should be so it is also NOT_AUTHORISED.
 */
int Authorizer::isAuthorized(const shared_ptr<ProcessNotification>& state) {
  assert(state != nullptr);
  set<int> futureStates, intersection, temp;
  int label;
  bool found = false;
  // In learning mode we only want to acquire every produced state, exiting syscalls do not need to be checked
  if (this->learning || dynamic_pointer_cast<ProcessSyscallExit>(state)) {
    this->processStates.push_back(state);
    return Authorizer::AUTHORISED;
  }
  shared_ptr<ProcessTermination> termination = dynamic_pointer_cast<ProcessTermination>(state);
  if (termination) {
	  futureStates = this->currentStates[termination->getSpid()];
    temp = this->automata->get_final_states();
    // Check if this tracee is in a final state
    set_intersection(futureStates.begin(), futureStates.end(),
                     temp.begin(), temp.end(),
                     inserter(intersection, intersection.begin()));
    if (intersection.empty()) {
      cout << "The traced thread is on the association numbers ";
	    this->printSet(futureStates);
      cout << endl << "But none of those states is final and the tracee is terminated" << endl;
      return Authorizer::NOT_FINAL;
    }
    return Authorizer::AUTHORISED;
  }
  shared_ptr<ProcessSyscallEntry> syscall = dynamic_pointer_cast<ProcessSyscallEntry>(state);
  // In enforce mode we want to check that every transition has been already seen
  assert(this->automata != nullptr);
  assert(syscall != nullptr);
  if (this->currentStates.find(syscall->getSpid()) == this->currentStates.end()) {
    if (this->currentStates.empty()) {
			// If this is the first traced process
      this->currentStates[syscall->getSpid()] = this->automata->get_initial_states();
    } else {
			// If an unknown SPID has been received
      for (auto it = this->childGenerators.begin();
           it != this->childGenerators.end() && !found;
           it++) {
        if ((*it)->getChildPid() > 0 && (*it)->getReturnValue() == syscall->getSpid()) {
          label = this->associations.find(*it);
          assert(label != Mapper::NOT_FOUND && label > 0);
          this->currentStates[syscall->getSpid()] = { label };
          this->childGenerators.erase(it);
          found = true;
        }
      }
      if (!found) {
        cout << "This state come from an unknown thread -> Not authorised" << endl;
        return Authorizer::NOT_AUTHORISED;
      }
    }
  }
  if ((label = this->associations.find(syscall)) == Mapper::NOT_FOUND) {
    cout << "State not found in the list of associations -> Not authorised" << endl;
    return Authorizer::NOT_AUTHORISED;
  }
	futureStates = this->automata->transition({this->currentStates[syscall->getSpid()] }, label);
  if (futureStates.empty()) {
    cout << "There are no possible transitions from ";
	  this->printSet(this->currentStates[syscall->getSpid()]);
    cout << " to " << label << endl;
    cout << "System call NOT authorised" << endl;
    return Authorizer::NOT_AUTHORISED;
  }
  cout << "Transition from ";
	this->printSet(this->currentStates[syscall->getSpid()]);
  this->currentStates[syscall->getSpid()] = futureStates;
  cout << " to ";
	this->printSet(futureStates);
  cout << " has been authorised" << endl;
  if (syscall->getChildPid() > 0) {
    assert(syscall->getReturnValue() > 0 && syscall->getReturnValue() < Tracer::MAX_PID);
    this->currentStates[(int) syscall->getReturnValue()] = this->currentStates[syscall->getSpid()];
  }
  if (syscall->getChildPid() == ProcessSyscallEntry::POSSIBLE_CHILD) {
    this->childGenerators.emplace_back(syscall);
  }
  // Check if this should be a final state -> possible automaton creation error
  if (ProcessSyscallEntry::exitSyscalls.find(syscall->getSyscall()) != ProcessSyscallEntry::exitSyscalls.end()) {
    temp = this->automata->get_final_states();
    if (temp.find(label) == temp.end()) {
      return Authorizer::NOT_FINAL;
    }
  }
  return Authorizer::AUTHORISED;
}

/**
 * Handle such a situation where an unauthorised process state occurs.
 * 
 * @param state The current ProcessState that is not authorised.
 * @return True if the target process can go on, False otherwise.
 */
bool Authorizer::handleUnauthorised(shared_ptr<ProcessNotification> state) {
  int choice;
  shared_ptr<ProcessSyscallEntry> syscall = dynamic_pointer_cast<ProcessSyscallEntry>(state);
  assert(syscall != nullptr);
  cout << "Warning! Found a Process syscall that has never been observed before!" << endl << endl;
  cout << "State observed:" << endl;
  syscall->print();
  do {
    cout << "Possible actions:" << endl;
    cout << "1 - Kill the target process" << endl;
    cout << "2 - Add the new state in the graph and allow it" << endl;
    cout << "Choice: ";
    cin >> choice;
    switch (choice) {
      case 1:
        TracingManager::kill_process();
        return false;
      case 2:
	      this->addTransition(syscall);
        break;
      default:
        cout << "Invalid choice" << endl;
        break;
    }
  } while (choice < 1 || choice > 2);
  return true;
}

/**
 * Handle such a situation where a state that is going to terminate the Tracee is not
 * marked as final in the automaton.
 * 
 * @param state The current ProcessState that is not marked as final.
 * @return True if the target process can go on, False otherwise.
 */
bool Authorizer::handleNonFinal(shared_ptr<ProcessNotification> state) {
  int choice;
  int state_label;
  set<int> new_final_states, final_states, temp;
  shared_ptr<ProcessSyscallEntry> syscall = dynamic_pointer_cast<ProcessSyscallEntry>(state);
  shared_ptr<ProcessTermination> termination = dynamic_pointer_cast<ProcessTermination>(state);
  cout << "Warning! Found a Process state that should has been marked as final state but it is not" << endl << endl;
  cout << "State observed:" << endl;
  state->print();
  do {
    cout << "Possible actions:" << endl;
    cout << "1 - Kill the target process" << endl;
    cout << "2 - Set the state as final" << endl;
    cout << "Choice: ";
    cin >> choice;
    switch (choice) {
      case 1:
        TracingManager::kill_process();
        return false;
      case 2:
        new_final_states = this->automata->get_final_states();
        if (syscall != nullptr) {
          state_label = this->associations.find(syscall);
          if (state_label == Mapper::NOT_FOUND) {
            ERROR("Trying to set a state as final but it is not in the associations file");
            return false;
          }
          cout << "The association number " << state_label << " will be marked as final" << endl;
          new_final_states.insert(state_label);
          this->automata->set_final_states(new_final_states);
        } else {
          // In this case every state where termination->getSpid() lays will be marked as final
          temp = this->currentStates[termination->getSpid()];
          for (const int& i : temp) {
            cout << "The association number " << i << " will be marked as final" << endl;
          }
          final_states = this->automata->get_final_states();
          set_union(final_states.begin(), final_states.end(),
                    temp.begin(), temp.end(),
                    inserter(new_final_states, new_final_states.begin()));
          this->automata->set_final_states(new_final_states);
        }
        break;
      default:
        cout << "Invalid choice" << endl;
        break;
    }
  } while (choice < 1 || choice > 2);
  return true;
}

/**
 * This performs a final check when every tracee is dead in order to ensure that every
 * current_state is marked as final.
 */
void Authorizer::checkFinalStates() {
  assert(this->automata != nullptr);
  string choice;
  set<int> intersection, temp, final_states;
  final_states = this->automata->get_final_states();
  for (auto& i : this->currentStates) {
    temp = i.second;
    set_intersection(final_states.begin(), final_states.end(),
                     temp.begin(), temp.end(),
                     inserter(intersection, intersection.begin()));
    if (intersection.empty()) {
      cout << "Warning! The tracee SPID " << i.first << " has terminated in a non final set of states ";
	    this->printSet(temp);
      cout << endl;
      do {
        cout << "Do you want to mark them as final? [yes/no] ";
        cin >> choice;
      } while (choice != "yes" && choice != "no");
      if (choice == "yes") {
        set_union(final_states.begin(), final_states.end(),
                  temp.begin(), temp.end(),
                  inserter(intersection, intersection.begin()));
        this->automata->set_final_states(intersection);
      }
    }
    intersection.clear();
  }
}


void Authorizer::printSet(set<int>& store) {
  cout << "( ";
  for (const int i : store) {
    cout << i << " ";
  }
  cout << ")";
}