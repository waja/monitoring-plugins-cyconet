***********
**ethMon**
***********

ethMon is an Icinga2/Nagios compatible Python plugin for network traffic monitoring on a specific interface.
Currently the carbon/graphite data is always in *bytes*.

Graph drawn from a collected data

.. image:: images/plugin_graph.png

In order to calculate the speed the plugin keeps the data from previous runs in ~/.ethMonCache.db

**Installation**
=================
* Download ethMon to the Icinga/Nagios plugin directory (`/usr/lib/nagios/plugins/` on Debian 10)
        * `Link <https://github.com/githubDante/ethMon/releases/download/v1.1.0/ethMon>`_
* Ensure that the executable bit of *ethMon* is set


**Configuration**
=================

* In order to use the plugin with Icinga the following configuration is needed:
    * in */usr/share/icinga2/include/command-plugins.conf* add the following

        .. code-block:: console

            template CheckCommand "ethMon-common" {
                command = [ PluginDir + "/ethMon" ]
                arguments = {
                        "-i" = {
                            value = "$interface$"
                            description = "Interface which will be monitored"
                        }
                        "-w" = {
                            value = "$speed_warn$"
                            description = "Warning threshold"
                        }
                        "-c" = {
                            value = "$speed_crit$"
                            description = "Critical threshold"
                        }
                        "-s" = {
                            value = "$speed_scale$"
                            description = "Speed scaling"
                        }
                        "--interval" = {
                            value = "$chk_interval$"
                            description = "Interval between the checks (in seconds)"
                        }
                }
                vars.speed_warn = 60
                vars.speed_crit = 100
                vars.speed_scale = "Mb"
                vars.chk_interval = 30
            }
            object CheckCommand "ethMon" {
                import "ethMon-common"
            }
        ..

    * then per host (or zone if the interface name match everywhere):

        .. code-block:: console

            apply Service "Traffic-enp3s5" {
                check_command = "ethMon"
                check_interval = 30
                vars.interface = "enp3s5"
            command_endpoint = host.vars.client_endpoint // Check executed on client node
            assign where host.vars.client_endpoint == "TheMonitoredHost" // The service is applied only to this node
            }
        ..

    * **NOTE**: The same value must be used for *check_interval & vars.chk_interval*

**Support for threshold ranges**

* `Icinga threshold ranges documentation <https://icinga.com/docs/icinga-2/latest/doc/05-service-monitoring/#threshold-ranges>`_


The plugin has partial support for the ranges described in the Icinga documentation. If used the ranges must be specified for both (warning & critical) parameters.
 Implemented are the following specifications:
    * min:max - The value must be outside the range in order the alert to be triggered
    * @min:max - The value must be inside the range in order the alert to be triggered
    * min: - The value must be below *min* or above 10*10^256 in order the alert to be triggered
    * @min: - The value must be between *min* and 10*10^256 in order the alert to be triggered
    * :max - The value must be below 0 and *max* in order the alert to be triggered
    * @:max - The value must be between 0 and *max* in order the alert to be triggered


**Motivation**
================

The plugin has been created as *check_eth* from Nagios Exchange refused to work in my current setup.
