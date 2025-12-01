import React, { useState } from 'react';
import { LogOut, Plus, Download, CheckCircle } from 'lucide-react';

export default function BillboardApp() {
  const [currentUser, setCurrentUser] = useState(null);
  const [token, setToken] = useState(localStorage.getItem('token') || '');
  const [email, setEmail] = useState('');
  const [password, setPassword] = useState('');

  const [billboards, setBillboards] = useState([]);
  const [pictures, setPictures] = useState([]);
  const [users, setUsers] = useState([]);

  const [showNotification, setShowNotification] = useState('');
  const [showUnassignConfirm, setShowUnassignConfirm] = useState(null);
  const [downloadProgress, setDownloadProgress] = useState(0);
  const [isDownloading, setIsDownloading] = useState(false);
  const [showAssignModal, setShowAssignModal] = useState(null);
  const [selectedClient, setSelectedClient] = useState('');
  const [showAddUserModal, setShowAddUserModal] = useState(false);
  const [formName, setFormName] = useState('');
  const [formEmail, setFormEmail] = useState('');
  const [formRole, setFormRole] = useState('');
  const [formPassword, setFormPassword] = useState('');
  const [showPasswordModal, setShowPasswordModal] = useState(null);
  const [showAddBillboardModal, setShowAddBillboardModal] = useState(false);
  const [billboardName, setBillboardName] = useState('');
  const [billboardLocation, setBillboardLocation] = useState('');
  const [showResetPasswordModal, setShowResetPasswordModal] = useState(null);
  const [resetPasswordValue, setResetPasswordValue] = useState('');
  const [loading, setLoading] = useState(false);

  const API_URL = import.meta.env.VITE_API_BASE_URL || 'http://localhost:5000/api';

  // API Helper
  const fetchAPI = async (endpoint, options = {}) => {
    try {
      setLoading(true);
      const headers = {
        'Content-Type': 'application/json',
        ...(token && { 'Authorization': `Bearer ${token}` }),
        ...options.headers
      };

      const response = await fetch(`${API_URL}${endpoint}`, {
        ...options,
        headers
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'API Error');
      }

      return await response.json();
    } catch (error) {
      console.error('API Error:', error);
      setShowNotification(`❌ ${error.message}`);
      throw error;
    } finally {
      setLoading(false);
    }
  };

  // Load Dashboard Data
  const loadDashboard = async () => {
    try {
      const [billboardsData, usersData, dashboardData] = await Promise.all([
        fetchAPI('/admin/billboards'),
        fetchAPI('/admin/users'),
        fetchAPI('/admin/dashboard')
      ]);
      setBillboards(billboardsData || []);
      setUsers(usersData || []);
    } catch (error) {
      console.error('Failed to load dashboard:', error);
    }
  };

  const handleLogin = async (e) => {
    e.preventDefault();
    try {
      const response = await fetch(`${API_URL}/auth/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password })
      });

      if (!response.ok) {
        const error = await response.json();
        throw new Error(error.error || 'Login failed');
      }

      const data = await response.json();
      setToken(data.token);
      localStorage.setItem('token', data.token);
      setCurrentUser(data.user);

      setEmail('');
      setPassword('');
      setShowNotification('✅ Login successful!');

      if (data.user.role === 'admin') {
        setTimeout(loadDashboard, 500);
      }
    } catch (error) {
      setShowNotification(`❌ ${error.message}`);
    }
  };

  const handleLogout = () => {
    setCurrentUser(null);
    setToken('');
    localStorage.removeItem('token');
    setBillboards([]);
    setUsers([]);
    setPictures([]);
  };

  const handleUnassign = async (billboardId) => {
    setIsDownloading(true);
    try {
      const response = await fetch(`${API_URL}/admin/billboards/${billboardId}/unassign`, {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${token}` }
      });

      if (response.ok) {
        const blob = await response.blob();
        const url = window.URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `billboard-${billboardId}.zip`;
        a.click();
        window.URL.revokeObjectURL(url);

        setShowNotification('✅ Billboard unassigned and pictures downloaded!');
        setShowUnassignConfirm(null);
        loadDashboard();
      }
    } catch (error) {
      setShowNotification(`❌ ${error.message}`);
    } finally {
      setIsDownloading(false);
    }
  };

  const handleAssign = async (billboardId) => {
    if (!selectedClient) return;
    try {
      await fetchAPI(`/admin/billboards/${billboardId}/assign`, {
        method: 'POST',
        body: JSON.stringify({ clientId: selectedClient })
      });
      setShowNotification('✅ Billboard assigned!');
      setShowAssignModal(null);
      setSelectedClient('');
      loadDashboard();
    } catch (error) {
      console.error('Assign failed:', error);
    }
  };

  const generatePassword = () => {
    const chars = 'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789!@#$%';
    let password = '';
    for (let i = 0; i < 12; i++) {
      password += chars.charAt(Math.floor(Math.random() * chars.length));
    }
    return password;
  };

  const handleCreateUser = async () => {
    if (!formName || !formEmail || !formRole) return;

    const generatedPassword = formPassword || generatePassword();
    try {
      await fetchAPI('/admin/users', {
        method: 'POST',
        body: JSON.stringify({
          name: formName,
          email: formEmail,
          password: generatedPassword,
          role: formRole
        })
      });

      setFormPassword(generatedPassword);
      setShowPasswordModal(true);
      setShowAddUserModal(false);
      setFormName('');
      setFormEmail('');
      setFormRole('');
      setShowNotification(`✅ User "${formName}" created!`);
      loadDashboard();
    } catch (error) {
      console.error('User creation failed:', error);
    }
  };

  const handleAddBillboard = async () => {
    if (!billboardName || !billboardLocation) return;
    try {
      await fetchAPI('/admin/billboards', {
        method: 'POST',
        body: JSON.stringify({
          name: billboardName,
          location: billboardLocation
        })
      });
      setShowNotification('✅ Billboard created!');
      setShowAddBillboardModal(false);
      setBillboardName('');
      setBillboardLocation('');
      loadDashboard();
    } catch (error) {
      console.error('Billboard creation failed:', error);
    }
  };

  const handleResetPassword = async () => {
    if (!resetPasswordValue) return;
    try {
      await fetchAPI(`/admin/users/${showResetPasswordModal}`, {
        method: 'PUT',
        body: JSON.stringify({ password: resetPasswordValue })
      });
      setShowNotification('✅ Password reset!');
      setShowResetPasswordModal(null);
      setResetPasswordValue('');
      loadDashboard();
    } catch (error) {
      console.error('Password reset failed:', error);
    }
  };

  const copyToClipboard = () => {
    navigator.clipboard.writeText(formPassword);
    setShowNotification('✅ Password copied!');
  };

  // ADMIN DASHBOARD
  if (currentUser?.role === 'admin') {
    return (
      <div className="min-h-screen bg-gray-50">
        <div className="bg-blue-900 text-white p-4 flex justify-between items-center">
          <h1 className="text-2xl font-bold">Billboard Tracking Admin</h1>
          <button onClick={handleLogout} className="flex items-center gap-2 bg-red-600 px-4 py-2 rounded hover:bg-red-700">
            <LogOut size={18} /> Logout
          </button>
        </div>

        {showNotification && (
          <div className="bg-green-100 border border-green-400 text-green-800 px-4 py-3 m-4 rounded flex items-center gap-2">
            <CheckCircle size={20} /> {showNotification}
          </div>
        )}

        {loading && <div className="text-center py-4">Loading...</div>}

        <div className="p-6">
          <div className="grid grid-cols-4 gap-4 mb-8">
            <div className="bg-white p-6 rounded shadow">
              <div className="text-3xl font-bold text-blue-600">{billboards.length}</div>
              <div className="text-gray-600">Total Billboards</div>
            </div>
            <div className="bg-white p-6 rounded shadow">
              <div className="text-3xl font-bold text-green-600">{billboards.filter(b => b.assignedClient).length}</div>
              <div className="text-gray-600">Assigned</div>
            </div>
            <div className="bg-white p-6 rounded shadow">
              <div className="text-3xl font-bold text-orange-600">{billboards.filter(b => !b.assignedClient).length}</div>
              <div className="text-gray-600">Unassigned</div>
            </div>
            <div className="bg-white p-6 rounded shadow">
              <div className="text-3xl font-bold text-purple-600">{users.length}</div>
              <div className="text-gray-600">Total Users</div>
            </div>
          </div>

          <div className="grid grid-cols-1 lg:grid-cols-3 gap-6">
            <div className="lg:col-span-2">
              <div className="bg-white rounded shadow p-6">
                <div className="flex justify-between items-center mb-4">
                  <h2 className="text-xl font-bold">Billboards Management</h2>
                  <button onClick={() => setShowAddBillboardModal(true)} className="bg-green-600 text-white px-4 py-2 rounded flex items-center gap-2 hover:bg-green-700">
                    <Plus size={18} /> Add Billboard
                  </button>
                </div>
                <div className="space-y-3">
                  {billboards.map(billboard => (
                    <div key={billboard._id} className="border p-4 rounded hover:bg-gray-50">
                      <div className="flex justify-between items-start">
                        <div>
                          <h3 className="font-bold text-lg">{billboard.name}</h3>
                          <p className="text-gray-600 text-sm">{billboard.location}</p>
                          <p className="text-xs text-gray-500 mt-1">📸 {billboard.pictures || 0} pictures</p>
                        </div>
                        <div className="flex gap-2">
                          {billboard.assignedClient && (
                            <button 
                              onClick={() => setShowUnassignConfirm(billboard._id)}
                              className="bg-red-500 text-white px-3 py-1 rounded text-sm hover:bg-red-600"
                            >
                              Unassign
                            </button>
                          )}
                          <button 
                            onClick={() => setShowAssignModal(billboard._id)}
                            className="bg-blue-500 text-white px-3 py-1 rounded text-sm hover:bg-blue-600"
                          >
                            Assign
                          </button>
                        </div>
                      </div>
                      <p className="text-xs mt-2 text-blue-600 font-semibold">
                        {billboard.assignedClient ? `✓ Assigned` : '⭕ Unassigned'}
                      </p>
                    </div>
                  ))}
                </div>
              </div>
            </div>

            <div className="bg-white rounded shadow p-6">
              <div className="flex justify-between items-center mb-4">
                <h2 className="text-lg font-bold">Users ({users.length})</h2>
                <button onClick={() => setShowAddUserModal(true)} className="bg-green-600 text-white px-3 py-2 rounded text-sm hover:bg-green-700">
                  <Plus size={16} />
                </button>
              </div>
              <div className="space-y-3 max-h-96 overflow-y-auto">
                {users.map(user => (
                  <div key={user._id} className="border p-3 rounded text-sm hover:bg-blue-50 flex justify-between items-start">
                    <div className="flex-1">
                      <p className="font-semibold">{user.name}</p>
                      <p className="text-gray-600 text-xs">{user.email}</p>
                      <p className="text-blue-600 text-xs mt-1 font-medium">
                        {user.role === 'photographer' ? '📷 Photographer' : '🏢 Client'}
                      </p>
                    </div>
                    <button
                      onClick={() => {
                        setShowResetPasswordModal(user._id);
                        setResetPasswordValue('');
                      }}
                      className="ml-2 px-2 py-1 bg-orange-500 text-white text-xs rounded hover:bg-orange-600"
                    >
                      🔑 Reset
                    </button>
                  </div>
                ))}
              </div>
            </div>
          </div>
        </div>

        {/* MODALS */}
        {showUnassignConfirm && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded shadow-lg max-w-md w-full p-6">
              <h3 className="text-lg font-bold mb-4">Confirm Unassignment</h3>
              <p className="text-gray-600 mb-6">This will download and delete all pictures.</p>
              <div className="flex gap-3">
                <button onClick={() => setShowUnassignConfirm(null)} className="flex-1 px-4 py-2 border rounded hover:bg-gray-50">
                  Cancel
                </button>
                <button onClick={() => handleUnassign(showUnassignConfirm)} disabled={isDownloading} className="flex-1 px-4 py-2 bg-red-600 text-white rounded hover:bg-red-700 disabled:opacity-50">
                  {isDownloading ? 'Downloading...' : 'Confirm'}
                </button>
              </div>
            </div>
          </div>
        )}

        {showAssignModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded shadow-lg max-w-md w-full p-6">
              <h3 className="text-lg font-bold mb-4">Assign Billboard</h3>
              <div className="mb-6">
                <label className="block text-sm font-semibold mb-2">Select Client</label>
                <select 
                  value={selectedClient} 
                  onChange={(e) => setSelectedClient(e.target.value)}
                  className="w-full border rounded px-3 py-2"
                >
                  <option value="">Choose a client...</option>
                  {users.filter(u => u.role === 'client').map(client => (
                    <option key={client._id} value={client._id}>{client.name}</option>
                  ))}
                </select>
              </div>
              <div className="flex gap-3">
                <button onClick={() => {setShowAssignModal(null); setSelectedClient('');}} className="flex-1 px-4 py-2 border rounded hover:bg-gray-50">
                  Cancel
                </button>
                <button 
                  onClick={() => handleAssign(showAssignModal)} 
                  disabled={!selectedClient}
                  className="flex-1 px-4 py-2 bg-blue-600 text-white rounded hover:bg-blue-700 disabled:opacity-50"
                >
                  Assign
                </button>
              </div>
            </div>
          </div>
        )}

        {showAddBillboardModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded shadow-lg max-w-md w-full p-6">
              <h3 className="text-lg font-bold mb-6">Create New Billboard</h3>
              <div className="space-y-4 mb-6">
                <div>
                  <label className="block text-sm font-semibold mb-2">Billboard Name</label>
                  <input 
                    type="text" 
                    value={billboardName}
                    onChange={(e) => setBillboardName(e.target.value)}
                    className="w-full border rounded px-3 py-2"
                    placeholder="e.g., Times Square NYC"
                  />
                </div>
                <div>
                  <label className="block text-sm font-semibold mb-2">Location</label>
                  <input 
                    type="text"
                    value={billboardLocation}
                    onChange={(e) => setBillboardLocation(e.target.value)}
                    className="w-full border rounded px-3 py-2"
                    placeholder="e.g., New York"
                  />
                </div>
              </div>
              <div className="flex gap-3">
                <button 
                  onClick={() => {
                    setShowAddBillboardModal(false);
                    setBillboardName('');
                    setBillboardLocation('');
                  }} 
                  className="flex-1 px-4 py-2 border rounded hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button 
                  onClick={handleAddBillboard}
                  disabled={!billboardName || !billboardLocation}
                  className="flex-1 px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
                >
                  ✓ Create
                </button>
              </div>
            </div>
          </div>
        )}

        {showAddUserModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded shadow-lg max-w-md w-full p-6">
              <h3 className="text-lg font-bold mb-6">Create New User</h3>
              <div className="space-y-4 mb-6">
                <div>
                  <label className="block text-sm font-semibold mb-2">Full Name</label>
                  <input 
                    type="text" 
                    value={formName}
                    onChange={(e) => setFormName(e.target.value)}
                    className="w-full border rounded px-3 py-2"
                    placeholder="e.g., John Smith"
                  />
                </div>
                <div>
                  <label className="block text-sm font-semibold mb-2">Email</label>
                  <input 
                    type="email"
                    value={formEmail}
                    onChange={(e) => setFormEmail(e.target.value)}
                    className="w-full border rounded px-3 py-2"
                    placeholder="e.g., john@example.com"
                  />
                </div>
                <div>
                  <label className="block text-sm font-semibold mb-2">Role</label>
                  <select 
                    value={formRole}
                    onChange={(e) => setFormRole(e.target.value)}
                    className="w-full border rounded px-3 py-2"
                  >
                    <option value="">-- Select Role --</option>
                    <option value="photographer">📷 Photographer</option>
                    <option value="client">🏢 Client</option>
                  </select>
                </div>
              </div>
              <div className="flex gap-3">
                <button 
                  onClick={() => {
                    setShowAddUserModal(false);
                    setFormName('');
                    setFormEmail('');
                    setFormRole('');
                  }} 
                  className="flex-1 px-4 py-2 border rounded hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button 
                  onClick={handleCreateUser}
                  disabled={!formName || !formEmail || !formRole}
                  className="flex-1 px-4 py-2 bg-green-600 text-white rounded hover:bg-green-700 disabled:opacity-50"
                >
                  ✓ Create
                </button>
              </div>
            </div>
          </div>
        )}

        {showPasswordModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded shadow-lg max-w-md w-full p-6">
              <h3 className="text-lg font-bold mb-4 text-green-600">✅ User Created!</h3>
              <div className="bg-green-50 border border-green-200 p-4 rounded mb-6">
                <p className="text-sm mb-3"><strong>Share these credentials:</strong></p>
                <div className="bg-white p-3 rounded border mb-3">
                  <p className="text-xs text-gray-600">Email:</p>
                  <p className="font-mono text-sm font-bold">{formEmail}</p>
                </div>
                <div className="bg-white p-3 rounded border mb-3">
                  <p className="text-xs text-gray-600">Password:</p>
                  <p className="font-mono text-sm font-bold break-all">{formPassword}</p>
                </div>
                <button 
                  onClick={copyToClipboard}
                  className="w-full bg-blue-600 text-white py-2 rounded hover:bg-blue-700 text-sm"
                >
                  📋 Copy
                </button>
              </div>
              <button 
                onClick={() => setShowPasswordModal(null)}
                className="w-full px-4 py-2 bg-gray-600 text-white rounded hover:bg-gray-700"
              >
                Done
              </button>
            </div>
          </div>
        )}

        {showResetPasswordModal && (
          <div className="fixed inset-0 bg-black bg-opacity-50 flex items-center justify-center p-4 z-50">
            <div className="bg-white rounded shadow-lg max-w-md w-full p-6">
              <h3 className="text-lg font-bold mb-4">🔑 Reset Password</h3>
              <div className="mb-6">
                <label className="block text-sm font-semibold mb-2">New Password</label>
                <input 
                  type="text"
                  value={resetPasswordValue}
                  onChange={(e) => setResetPasswordValue(e.target.value)}
                  className="w-full border rounded px-3 py-2"
                  placeholder="Enter new password"
                />
              </div>
              <div className="flex gap-3">
                <button 
                  onClick={() => setShowResetPasswordModal(null)}
                  className="flex-1 px-4 py-2 border rounded hover:bg-gray-50"
                >
                  Cancel
                </button>
                <button 
                  onClick={handleResetPassword}
                  disabled={!resetPasswordValue}
                  className="flex-1 px-4 py-2 bg-orange-600 text-white rounded hover:bg-orange-700 disabled:opacity-50"
                >
                  ✓ Reset
                </button>
              </div>
            </div>
          </div>
        )}
      </div>
    );
  }

  // LOGIN
  return (
    <div className="min-h-screen bg-gradient-to-br from-blue-900 to-blue-700 flex items-center justify-center p-4">
      <div className="bg-white rounded shadow-lg max-w-md w-full p-8">
        <h1 className="text-3xl font-bold text-center mb-8 text-gray-800">Billboard Tracking</h1>
        <div className="space-y-4">
          <div>
            <label className="block text-sm font-semibold mb-2">Email</label>
            <input type="email" value={email} onChange={e => setEmail(e.target.value)} className="w-full border rounded px-4 py-2" placeholder="admin@test.com" />
          </div>
          <div>
            <label className="block text-sm font-semibold mb-2">Password</label>
            <input type="password" value={password} onChange={e => setPassword(e.target.value)} className="w-full border rounded px-4 py-2" />
          </div>
          <button onClick={handleLogin} disabled={loading} className="w-full bg-blue-600 text-white py-2 rounded font-bold hover:bg-blue-700 disabled:opacity-50">
            {loading ? 'Logging in...' : 'Login'}
          </button>
        </div>
        <div className="mt-6 p-4 bg-blue-50 rounded text-sm text-gray-700">
          <p className="font-semibold mb-2">Demo Accounts:</p>
          <p>👤 Admin: admin@test.com</p>
          <p>📷 Photographer: photographer@test.com</p>
          <p>🏢 Client: client@test.com</p>
          <p className="text-xs mt-2 text-gray-600">(Use any password)</p>
        </div>
      </div>
    </div>
  );
}
