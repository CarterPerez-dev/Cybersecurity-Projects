#ifndef VIEW_HPP
#define VIEW_HPP
#include "../stats/protocolStats.hpp"
#include <ftxui/dom/elements.hpp>

class View {
  public:
	static ftxui::Element render(const StatsSnapshot &data, const std::string &interface, const std::string &filter,
								 bool capture_finished, std::chrono::seconds timer);

  private:
	static ftxui::Element render_header(const StatsSnapshot &data, const std::string &interface,
										const std::string &filter);
	static ftxui::Element render_stats(const StatsSnapshot &data);

	static ftxui::Element render_transport(const StatsSnapshot &data);
	static ftxui::Element render_application(const StatsSnapshot &data);
	static ftxui::Element render_ip(const StatsSnapshot &data);
	static ftxui::Element render_pairs(const StatsSnapshot &data);
	static ftxui::Element render_bandwidth(const StatsSnapshot &data);
	static ftxui::Element render_packets(const StatsSnapshot &data);

	static ftxui::Element render_footer(bool capture_finished, std::chrono::seconds timer);
};

#endif // VIEW_HPP
