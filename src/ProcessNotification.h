#ifndef PROCESSNOTIFICATION_H
#define PROCESSNOTIFICATION_H
#include <memory>
#include <string>
#include <boost/property_tree/ptree.hpp>

class ProcessNotification {
  friend class Tracer;
public:
  ProcessNotification(std::string notification_origin, int pid, int spid);
  ProcessNotification(std::string flat);
  ProcessNotification(const ProcessNotification& orig);
  ProcessNotification() = default;
  virtual ~ProcessNotification() = default;
  std::string get_executable_name() const;
  void set_executable_name(const std::string& syscall_origin);
  pid_t get_pid() const;
  pid_t get_spid() const;
  bool is_authorised() const;
  std::string get_timestamp() const;
  virtual bool authorise();
  virtual void print() const;
  virtual std::string serialize() const;
  virtual boost::property_tree::ptree get_xes() const;
  static std::shared_ptr<ProcessNotification> deserialize(std::string flat, bool no_backtrace);
protected:
  static const std::string FIELD_SEPARATOR;
  static const std::string AUTHORISED_SPEC;
  static const std::string NOT_AUTHORISED_SPEC;
  virtual void set_notification_origin(std::string notification_origin);
  virtual void set_pid(pid_t pid);
  virtual void set_spid(pid_t spid);
  virtual void set_timestamp();
private:
  std::string _notification_origin;
  std::string _timestamp;
  pid_t _pid = -1;
  pid_t _spid = -1;
  bool _authorised = false;
};

#endif /* PROCESSNOTIFICATION_H */