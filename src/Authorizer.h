/*
 * File:   Authoriser.h
 * Author: Matteo De Giorgi
 *
 * Created on 09 November 2016, 17:21
 */

#ifndef PTRACER_AUTHORIZER_H
#define PTRACER_AUTHORIZER_H
#define ERROR(message) cerr << ((string(const_cast< char *>(__func__)) + \
                                 string("@") + to_string(__LINE__) + \
                                 string(" -> ") + message + "\n").c_str())
#include <libalf/alf.h>
#include <amore++/nondeterministic_finite_automaton.h>
#include <vector>
#include <memory>
#include "Mapper.h"
#include "TracingManager.h"

class Authorizer {
public:
  static const int AUTHORISED;
  static const int NOT_AUTHORISED;
  static const int NOT_FINAL;
  Authorizer(const std::string graphPath, const std::string associationsPath, bool learning);
	void process(std::shared_ptr<ProcessNotification> syscall);
	void terminate();
  bool dotOutput(const std::string& filePath) const;
	operator std::string() const;

protected:
  void buildAutomata();
  bool save();
  bool addTransition(std::shared_ptr<ProcessSyscallEntry> state);

private:
  std::unique_ptr<amore::nondeterministic_finite_automaton> automata;
  std::map<pid_t, std::set<int>> currentStates;
  std::vector<std::shared_ptr<ProcessSyscallEntry>> childGenerators;
  const std::string graphPath;
  const bool learning;
  Mapper associations;
  std::vector<std::shared_ptr<ProcessNotification>> processStates;
  bool importAutomaton();
  int isAuthorized(const std::shared_ptr<ProcessNotification>& state);
  bool handleUnauthorised(std::shared_ptr<ProcessNotification> state);
  bool handleNonFinal(std::shared_ptr<ProcessNotification> state);
  void checkFinalStates();
  void printSet(std::set<int>& store) const;
};

#endif /* PTRACER_AUTHORIZER_H */