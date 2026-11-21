import { StrictMode } from 'react';
import { createRoot } from 'react-dom/client';
import { HashRouter, Navigate, Route, Routes, useLocation } from 'react-router-dom';
import './styles.css';
import { UiProvider, Empty } from './ui';
import { Session, Shell } from './Shell';
import { Login } from './pages/login';
import * as M from './pages/main';
import * as P from './pages/projects';
import * as F from './pages/findings';
import * as A from './pages/ai';
import * as O from './pages/ops';
import * as G from './pages/admin';

if (localStorage.getItem('sentra-theme') === 'light') document.documentElement.classList.add('light');

// Deep links from the v2 handoff UI (OPEN-UI.html) map onto the product routes.
const ALIASES: [string, string][] = [['/overview', '/'], ['/ops', '/'], ['/ops/control', '/'], ['/ops/onboard', '/projects/new'], ['/ops/sources', '/integrations'], ['/ops/pipeline', '/ci'], ['/ops/channels', '/automation/channels'], ['/ops/routing', '/automation/rules'], ['/ops/schedules', '/automation/schedules'], ['/ops/jobs', '/automation/jobs'], ['/ops/agents', '/agents'], ['/ops/access', '/admin'], ['/ops/requirements', '/requirements'], ['/ai-config', '/agents'], ['/ai-credentials', '/agents'], ['/ai-history', '/investigations'], ['/lab', '/'], ['/settings', '/admin/settings'], ['/report', '/reports'], ['/campaign', '/campaigns'], ['/project', '/projects'], ['/finding', '/findings'], ['/asset', '/assets'], ['/investigation', '/investigations']];

function Authed() {
  const loc = useLocation();
  return <Session><Shell><Routes location={loc}>
    {ALIASES.map(([from, to]) => <Route key={from} path={from} element={<Navigate to={to} replace />} />)}
    <Route path="/" element={<M.Overview />} />
    <Route path="/notifications" element={<M.Notifications />} />
    <Route path="/projects" element={<P.ProjectList />} />
    <Route path="/projects/new" element={<P.NewProject />} />
    <Route path="/projects/:id" element={<P.ProjectOverview />} />
    <Route path="/projects/:id/onboarding" element={<P.Onboarding />} />
    <Route path="/projects/:id/inventory" element={<P.Inventory />} />
    <Route path="/projects/:id/deployments" element={<P.Deployments />} />
    <Route path="/projects/:id/import" element={<P.Import />} />
    <Route path="/projects/:id/access" element={<P.Access />} />
    <Route path="/projects/:id/knowledge" element={<P.Knowledge />} />
    <Route path="/projects/:id/attack-paths" element={<P.AttackPaths />} />
    <Route path="/projects/:id/external" element={<P.External />} />
    <Route path="/projects/:id/activity" element={<P.Activity />} />
    <Route path="/findings" element={<F.FindingList />} />
    <Route path="/findings/:id" element={<F.FindingDetail />} />
    <Route path="/advisories" element={<M.Advisories />} />
    <Route path="/advisories/new" element={<M.NewAdvisory />} />
    <Route path="/advisories/:id" element={<M.Advisory />} />
    <Route path="/assets" element={<M.Assets />} />
    <Route path="/assets/:id" element={<M.Asset />} />
    <Route path="/components/:id" element={<M.Component />} />
    <Route path="/drift" element={<M.Drift />} />
    <Route path="/campaigns" element={<M.Campaigns />} />
    <Route path="/coverage" element={<M.Coverage />} />
    <Route path="/investigations" element={<A.InvestigationList />} />
    <Route path="/investigations/new" element={<A.NewInvestigation />} />
    <Route path="/investigations/:id" element={<A.InvestigationView />} />
    <Route path="/analysis" element={<A.Analysis />} />
    <Route path="/agents" element={<A.Agents />} />
    <Route path="/automation" element={<O.Alerts />} />
    <Route path="/automation/rules" element={<O.Rules />} />
    <Route path="/automation/policies" element={<O.Policies />} />
    <Route path="/automation/channels" element={<O.Channels />} />
    <Route path="/automation/schedules" element={<O.Schedules />} />
    <Route path="/automation/jobs" element={<O.Jobs />} />
    <Route path="/automation/deliveries" element={<O.Deliveries />} />
    <Route path="/reports" element={<O.Reports />} />
    <Route path="/reports/:id" element={<O.Report />} />
    <Route path="/integrations" element={<O.Integrations />} />
    <Route path="/ci" element={<O.CiSetup />} />
    <Route path="/ci/evaluation/:id" element={<O.Evaluation />} />
    <Route path="/admin" element={<G.Members />} />
    <Route path="/admin/invitations" element={<G.Invitations />} />
    <Route path="/admin/mappings" element={<G.Mappings />} />
    <Route path="/admin/secrets" element={<G.Secrets />} />
    <Route path="/admin/settings" element={<G.Settings />} />
    <Route path="/audit" element={<G.Audit />} />
    <Route path="/requirements" element={<G.Requirements />} />
    <Route path="*" element={<Empty title="Page not found">Check the address or use the navigation.</Empty>} />
  </Routes></Shell></Session>;
}

createRoot(document.getElementById('root')!).render(<StrictMode><UiProvider><HashRouter><Routes>
  <Route path="/login" element={<Login />} />
  <Route path="*" element={<Authed />} />
</Routes></HashRouter></UiProvider></StrictMode>);
