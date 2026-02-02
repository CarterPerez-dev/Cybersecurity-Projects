"""
ⒸAngelaMos | 2026
visualization.py

Matplotlib chart generation for network traffic analysis
"""

from pathlib import Path

import matplotlib


matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.figure import Figure

from netanal.constants import ByteUnits, ChartDefaults, ProtocolColors
from netanal.models import CaptureStatistics, Protocol


def _get_protocol_hex_color(protocol: Protocol) -> str:
    """
    Get matplotlib hex color for a protocol
    """
    return ProtocolColors.HEX.get(
        protocol.value,
        ProtocolColors.HEX["OTHER"]
    )


def create_protocol_pie_chart(
    stats: CaptureStatistics,
    title: str = "Protocol Distribution",
) -> Figure:
    """
    Create pie chart showing protocol distribution by packet count
    """
    fig, ax = plt.subplots(figsize=ChartDefaults.FIGSIZE_SQUARE)

    protocols = list(stats.protocol_distribution.keys())
    counts = [stats.protocol_distribution[p] for p in protocols]
    colors = [_get_protocol_hex_color(p) for p in protocols]
    labels = [p.value for p in protocols]

    autotexts = ax.pie(
        counts,
        labels=labels,
        colors=colors,
        autopct="%1.1f%%",
        startangle=90,
        pctdistance=0.85,
    )[2]

    for autotext in autotexts:
        autotext.set_fontsize(ChartDefaults.FONT_SIZE_SMALL)
        autotext.set_color("white")
        autotext.set_fontweight("bold")

    ax.set_title(
        title,
        fontsize=ChartDefaults.FONT_SIZE_LARGE,
        fontweight="bold"
    )
    plt.tight_layout()

    return fig


def create_protocol_bar_chart(
    stats: CaptureStatistics,
    title: str = "Protocol Distribution",
) -> Figure:
    """
    Create bar chart showing protocol distribution
    """
    fig, ax = plt.subplots(figsize=ChartDefaults.FIGSIZE_STANDARD)

    protocols = sorted(
        stats.protocol_distribution.keys(),
        key=lambda p: stats.protocol_distribution[p],
        reverse=True,
    )
    counts = [stats.protocol_distribution[p] for p in protocols]
    colors = [_get_protocol_hex_color(p) for p in protocols]
    labels = [p.value for p in protocols]

    bars = ax.bar(
        labels,
        counts,
        color=colors,
        edgecolor="black",
        linewidth=ChartDefaults.LINE_WIDTH_THIN,
    )

    for bar, count in zip(bars, counts, strict=False):
        ax.text(
            bar.get_x() + bar.get_width() / 2,
            bar.get_height() + max(counts) * 0.01,
            f"{count:,}",
            ha="center",
            va="bottom",
            fontsize=ChartDefaults.FONT_SIZE_SMALL,
        )

    ax.set_xlabel("Protocol", fontsize=ChartDefaults.FONT_SIZE_MEDIUM)
    ax.set_ylabel(
        "Packet Count",
        fontsize=ChartDefaults.FONT_SIZE_MEDIUM
    )
    ax.set_title(
        title,
        fontsize=ChartDefaults.FONT_SIZE_LARGE,
        fontweight="bold"
    )
    ax.grid(axis="y", alpha=ChartDefaults.GRID_ALPHA)
    plt.tight_layout()

    return fig


def create_top_talkers_chart(
    stats: CaptureStatistics,
    limit: int = 10,
    title: str = "Top Talkers by Traffic Volume",
) -> Figure:
    """
    Create horizontal bar chart showing top talkers
    """
    fig, ax = plt.subplots(figsize=ChartDefaults.FIGSIZE_TALL)

    top_talkers = stats.get_top_talkers(limit)

    if not top_talkers:
        ax.text(
            0.5,
            0.5,
            "No data available",
            ha="center",
            va="center"
        )
        return fig

    ips = [e.ip_address for e in reversed(top_talkers)]
    sent_bytes = [
        e.bytes_sent / ByteUnits.BYTES_PER_KB
        for e in reversed(top_talkers)
    ]
    recv_bytes = [
        e.bytes_received / ByteUnits.BYTES_PER_KB
        for e in reversed(top_talkers)
    ]

    y_pos = range(len(ips))

    ax.barh(
        y_pos,
        sent_bytes,
        height=ChartDefaults.BAR_HEIGHT,
        label="Sent",
        color=ProtocolColors.HEX["TCP"],
        edgecolor="black",
        linewidth=ChartDefaults.LINE_WIDTH_THIN,
    )
    ax.barh(
        [y + ChartDefaults.BAR_HEIGHT for y in y_pos],
        recv_bytes,
        height=ChartDefaults.BAR_HEIGHT,
        label="Received",
        color=ProtocolColors.HEX["UDP"],
        edgecolor="black",
        linewidth=ChartDefaults.LINE_WIDTH_THIN,
    )

    ax.set_yticks([y + ChartDefaults.BAR_HEIGHT / 2 for y in y_pos])
    ax.set_yticklabels(ips)
    ax.set_xlabel(
        "Traffic (KB)",
        fontsize=ChartDefaults.FONT_SIZE_MEDIUM
    )
    ax.set_ylabel("IP Address", fontsize=ChartDefaults.FONT_SIZE_MEDIUM)
    ax.set_title(
        title,
        fontsize=ChartDefaults.FONT_SIZE_LARGE,
        fontweight="bold"
    )
    ax.legend(loc="lower right")
    ax.grid(axis="x", alpha=ChartDefaults.GRID_ALPHA)
    plt.tight_layout()

    return fig


def create_bandwidth_chart(
    stats: CaptureStatistics,
    title: str = "Bandwidth Over Time",
) -> Figure:
    """
    Create line chart showing bandwidth over time
    """
    fig, ax = plt.subplots(figsize=ChartDefaults.FIGSIZE_WIDE)

    if not stats.bandwidth_samples:
        ax.text(
            0.5,
            0.5,
            "No bandwidth data available",
            ha="center",
            va="center"
        )
        return fig

    samples = stats.bandwidth_samples
    base_time = samples[0].timestamp if samples else 0

    times = [(s.timestamp - base_time) for s in samples]
    bps = [s.bytes_per_second / ByteUnits.BYTES_PER_KB for s in samples]
    pps = [s.packets_per_second for s in samples]

    ax.plot(
        times,
        bps,
        color=ProtocolColors.HEX["TCP"],
        linewidth=ChartDefaults.LINE_WIDTH_NORMAL,
        label="Bandwidth (KB/s)",
        marker="o",
        markersize=ChartDefaults.MARKER_SIZE,
    )

    ax2 = ax.twinx()
    ax2.plot(
        times,
        pps,
        color=ProtocolColors.HEX["HTTP"],
        linewidth=ChartDefaults.LINE_WIDTH_NORMAL,
        label="Packets/s",
        linestyle="--",
        marker="s",
        markersize=ChartDefaults.MARKER_SIZE,
    )

    ax.set_xlabel(
        "Time (seconds)",
        fontsize=ChartDefaults.FONT_SIZE_MEDIUM
    )
    ax.set_ylabel(
        "Bandwidth (KB/s)",
        fontsize=ChartDefaults.FONT_SIZE_MEDIUM,
        color=ProtocolColors.HEX["TCP"]
    )
    ax2.set_ylabel(
        "Packets/s",
        fontsize=ChartDefaults.FONT_SIZE_MEDIUM,
        color=ProtocolColors.HEX["HTTP"]
    )
    ax.set_title(
        title,
        fontsize=ChartDefaults.FONT_SIZE_LARGE,
        fontweight="bold"
    )

    lines1, labels1 = ax.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax.legend(lines1 + lines2, labels1 + labels2, loc="upper right")

    ax.grid(alpha=ChartDefaults.GRID_ALPHA)
    plt.tight_layout()

    return fig


def save_chart(
    fig: Figure,
    filepath: Path,
    dpi: int = ChartDefaults.DPI
) -> None:
    """
    Save matplotlib figure to file
    """
    fig.savefig(
        filepath,
        dpi=dpi,
        bbox_inches="tight",
        facecolor="white"
    )
    plt.close(fig)


def generate_all_charts(
    stats: CaptureStatistics,
    output_dir: Path,
    prefix: str = "capture",
) -> list[Path]:
    """
    Generate all charts and save to output directory
    """
    output_dir.mkdir(parents=True, exist_ok=True)
    generated: list[Path] = []

    if stats.protocol_distribution:
        pie_path = output_dir / f"{prefix}_protocol_pie.png"
        fig = create_protocol_pie_chart(stats)
        save_chart(fig, pie_path)
        generated.append(pie_path)

        bar_path = output_dir / f"{prefix}_protocol_bar.png"
        fig = create_protocol_bar_chart(stats)
        save_chart(fig, bar_path)
        generated.append(bar_path)

    if stats.endpoints:
        talkers_path = output_dir / f"{prefix}_top_talkers.png"
        fig = create_top_talkers_chart(stats)
        save_chart(fig, talkers_path)
        generated.append(talkers_path)

    if stats.bandwidth_samples:
        bandwidth_path = output_dir / f"{prefix}_bandwidth.png"
        fig = create_bandwidth_chart(stats)
        save_chart(fig, bandwidth_path)
        generated.append(bandwidth_path)

    return generated


__all__ = [
    "create_bandwidth_chart",
    "create_protocol_bar_chart",
    "create_protocol_pie_chart",
    "create_top_talkers_chart",
    "generate_all_charts",
    "save_chart",
]
