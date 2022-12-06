#ifndef PTRACER_PROCESSNOTIFICATION_H
#define PTRACER_PROCESSNOTIFICATION_H
#include <memory>
#include <string>

class ProcessNotification {
  friend class Tracer;
public:
  ProcessNotification(std::string notification_origin, int pid, int spid);
  virtual ~ProcessNotification() = default;
  [[nodiscard]] std::string getExecutableName() const;
  void setExecutableName(const std::string& syscall_origin);
  [[nodiscard]] pid_t getPid() const;
  [[nodiscard]] pid_t getSpid() const;
  [[nodiscard]] bool isAuthorised() const;
  [[nodiscard]] unsigned long long getTimestamp() const;
  virtual bool authorise();
  virtual void print() const;
protected:
  virtual void setNotificationOrigin(std::string notification_origin);
  virtual void setPid(pid_t pid);
  virtual void setSpid(pid_t spid);
  virtual void setTimestamp();
private:
  std::string notificationOrigin;
  unsigned long long timestamp = 0;
  pid_t pid = -1;
  pid_t spid = -1;
  bool authorised = false;
};

#endif /* PTRACER_PROCESSNOTIFICATION_H */