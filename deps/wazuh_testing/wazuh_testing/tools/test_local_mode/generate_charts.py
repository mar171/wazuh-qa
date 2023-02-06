"""
Script to generate the performance charts.

As preconditions, we have to have the following csv file data in the same script path:

- syslog_alerts.csv
- footprint.csv
"""
import os
import datetime
import warnings
import pandas as pd
import matplotlib.pyplot as plt


def generate_simple_chart(x_data, y_data, legend_label=None, x_label=None, y_label=None, title=None, output=None):
    """Generate a simple linear chart with two variables.

    Args:
        x_data (pandas.core.series.Serie): X axis data
        y_data (pandas.core.series.Serie): Y axis data.
        legend_label (str): Legend label.
        x_label (str): X axis label.
        y_label (str): Y axis label.
        title (str): Chart title.
        output (str): Output chart file name.
    """
    plt.plot(x_data, y_data, label=legend_label, linewidth=1)
    plt.margins(0.01, 0.01)
    plt.xlabel(x_label)
    plt.ylabel(y_label)
    if title:
        plt.title(title, fontsize=20)
    if legend_label:
        plt.legend()
    plt.tight_layout()

    # Save the chart figure
    plt.savefig(output, dpi=1200, format='png')

    # Clean plots for the next iteration
    plt.clf()


def generate_chart_image(title=None, output=None):
    """Generate a simple linear chart with two variables.

    Args:
        x_data (pandas.core.series.Serie): X axis data
        y_data (pandas.core.series.Serie): Y axis data.
        legend_label (str): Legend label.
        x_label (str): X axis label.
        y_label (str): Y axis label.
        title (str): Chart title.
        output (str): Output chart file name.
    """
    # plt.plot(x_data, y_data, label=legend_label, linewidth=1)
    plt.margins(0.01, 0.01)

    if title:
        plt.title(title, fontsize=20)

    plt.tight_layout()

    # Save the chart figure
    plt.savefig(output, dpi=1200, format='png')

    # Clean plots for the next iteration
    plt.clf()


def plot_alerts(source_file, alerts_monitoring=True, syslog_alerts=True, dir=None):
    """Generate the syslog alerts chart.

    Args:
        source_file (str): Source CSV file path.
        output_file_name (str): Output chart file name.
    """
    path_comparision = 'alerts_comparision.png'
    path_global = 'alerts_global.png'

    if dir:
        path_comparision = os.path.join(dir, 'alerts_comparision.png')
        path_global = os.path.join(dir, 'alerts_global.png')

    dataframe = pd.read_csv(source_file)

    interval_frame = dataframe['seconds']
    figure, axis = plt.subplots()
    print(dataframe)
    print(dataframe['epi'])
    axis.plot(dataframe['seconds'], dataframe['epi'], label='Expected Alerts')

# , x_label='Time (s)' y_label='Alerts'
    if syslog_alerts:
        axis.plot(dataframe['seconds'], dataframe['num_syslog'], label='Received Alerts by the Syslog server')
        print("Total syslog")
        print(sum(dataframe['num_syslog']))

    if alerts_monitoring:
        print("Total alerts")
        print(sum(dataframe['num_alerts']))
        axis.plot(dataframe['seconds'], dataframe['num_alerts'], label='Triggered Alerts')

    axis.legend()

    generate_chart_image(title='Alerts comparision', output=path_comparision)

    plt.clf()

    # Bar Plot
    bar_figure, bar_ax = plt.subplots()

    fields = ['Expected Alerts', 'Alerts', 'Syslog Alerts']
    values = [sum(dataframe['epi']), sum(dataframe['num_alerts']), sum(dataframe['num_syslog'])]

    bar_ax.bar(fields, values)
    generate_chart_image(title='Alerts Global', output=path_global)



def plot_footprint(source_file, output_file_name, unit, directory):
    """Generate the footprint charts (one per daemon and stat).

    Args:
        source_file (str): Source CSV file path.
        output_file_name (str): Output chart file name.
    """
    dataframe = pd.read_csv(source_file)
    footprint_stats = {
        'CPU(%)': 'cpu',
        f'RSS({unit})': 'rss',
        f'disk_read({unit})': 'disk_read',
        f'disk_written({unit})': 'disk_written',
        f'VMS({unit})': 'vms',
        'FD': 'fd'
    }
    daemons = ['ossec-analysisd', 'ossec-syscheckd', 'ossec-logcollector']

    # Generate one different dataframe per daemon
    dataframes = {daemon.replace('ossec-', ''): dataframe[dataframe['wazuh-daemon'] == daemon] for daemon in daemons}

    # Generate one chart per daemon and stat
    for daemon, split_dataframe in dataframes.items():
        for stat, stat_name in footprint_stats.items():
            file_name = f"{output_file_name}_{daemon}_{stat_name}.png"
            file_path = os.path.join(directory, file_name)
            generate_simple_chart(split_dataframe['seconds'], split_dataframe[stat], title=stat, output=file_path)


def main():
    """Main process to read and generate the syslog alerts and footprint charts."""
    # Mute annoying warnings
    warnings.filterwarnings('ignore')

    date_time = datetime.datetime.now().strftime("%Y%m%d%H%M%S")
    syslog_alerts_data = 'syslog_alerts.csv'
    footprint_data = 'footprint.csv'

    # Generate the charts
    plot_syslog_alerts(syslog_alerts_data, f"{date_time}_received_syslog_alerts.png")
    plot_footprint(footprint_data, f"{date_time}")


if __name__ == '__main__':
    main()
