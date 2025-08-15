package postgresql

func (p *PostgreSQLBackend) LeadershipChange(active bool) {
	p.active.Store(active)
}
