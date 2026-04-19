// ©AngelaMos | 2026
// attack-map.tsx

import { CircleMarker, MapContainer, TileLayer, Tooltip } from 'react-leaflet'
import type { Attacker } from '@/api/types'
import styles from './attack-map.module.scss'

const MAP_CENTER: [number, number] = [20, 0]
const MAP_ZOOM = 2
const MIN_RADIUS = 4
const MAX_RADIUS = 18
const TILE_URL = 'https://{s}.basemaps.cartocdn.com/dark_all/{z}/{x}/{y}{r}.png'
const TILE_ATTR =
  '&copy; <a href="https://www.openstreetmap.org/copyright">OSM</a> &copy; <a href="https://carto.com/">CARTO</a>'

interface AttackMapProps {
  attackers: Attacker[]
}

export function AttackMap({ attackers }: AttackMapProps) {
  const maxEvents = Math.max(...attackers.map((a) => a.total_events), 1)

  return (
    <div className={styles.wrapper}>
      <MapContainer
        center={MAP_CENTER}
        zoom={MAP_ZOOM}
        className={styles.map}
        scrollWheelZoom={false}
        zoomControl={false}
      >
        <TileLayer url={TILE_URL} attribution={TILE_ATTR} />

        {attackers.map((attacker) => {
          if (!attacker.geo.latitude && !attacker.geo.longitude) return null

          const ratio = attacker.total_events / maxEvents
          const radius = MIN_RADIUS + ratio * (MAX_RADIUS - MIN_RADIUS)

          return (
            <CircleMarker
              key={attacker.id}
              center={[attacker.geo.latitude, attacker.geo.longitude]}
              radius={radius}
              pathOptions={{
                color: 'oklch(0.6 0.22 25)',
                fillColor: 'oklch(0.6 0.22 25)',
                fillOpacity: 0.6,
                weight: 1,
              }}
            >
              <Tooltip>
                <strong>{attacker.ip}</strong>
                <br />
                {attacker.geo.country}{' '}
                {attacker.geo.city ? `- ${attacker.geo.city}` : ''}
                <br />
                Events: {attacker.total_events}
              </Tooltip>
            </CircleMarker>
          )
        })}
      </MapContainer>
    </div>
  )
}
