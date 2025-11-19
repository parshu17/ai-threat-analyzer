# modules/visualizer.py
import plotly.express as px
import pandas as pd

def top_n_table(df, column, n=10):
    """
    Returns DataFrame with top n values by count for a column.
    """
    if column not in df.columns:
        return pd.DataFrame()
    top = df[column].value_counts().reset_index().head(n)
    top.columns = [column, "count"]
    return top

def bar_count(df, column, title="Counts"):
    top = top_n_table(df, column)
    if top.empty:
        return None
    fig = px.bar(top, x=column, y="count", title=title)
    return fig

def time_series_count(df, time_col, freq="D", title="Events over time"):
    """
    df: DataFrame with time_col parseable as datetime
    freq: 'D' daily, 'H' hourly, etc.
    """
    df2 = df.copy()
    df2[time_col] = pd.to_datetime(df2[time_col], errors="coerce")
    df2 = df2.dropna(subset=[time_col])
    series = df2.set_index(time_col).resample(freq).size().reset_index(name="count")
    fig = px.line(series, x=time_col, y="count", title=title)
    return fig

# in modules/visualizer.py (append)
def world_map(df, lat_col="geo_lat", lon_col="geo_lon", hover_cols=None, title="Attack Map"):
    import plotly.express as px
    import pandas as pd
    if lat_col not in df.columns or lon_col not in df.columns:
        return None
    df2 = df.dropna(subset=[lat_col, lon_col])
    # convert to numeric
    df2[lat_col] = pd.to_numeric(df2[lat_col], errors="coerce")
    df2[lon_col] = pd.to_numeric(df2[lon_col], errors="coerce")
    if df2.empty:
        return None
    hover = hover_cols if hover_cols else []
    fig = px.scatter_geo(df2, lat=lat_col, lon=lon_col,
                         hover_name=hover[0] if hover else None,
                         hover_data=hover,
                         scope='world',
                         title=title)
    fig.update_layout(height=500, margin={"r":0,"t":30,"l":0,"b":0})
    return fig
