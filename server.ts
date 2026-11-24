import 'dotenv/config';
import crypto from 'node:crypto';
import fs from 'node:fs';
import path from 'node:path';
import bcrypt from 'bcryptjs';
import express, { type Request, type Response } from 'express';
import rateLimit from 'express-rate-limit';
import {
  authenticateToken,
  isNonEmptyString,
  isValidDateOnly,
  isValidEmail,
  requireAdmin,
  signAccessToken,
  type AuthenticatedRequest,
} from './server/auth.ts';
import { db } from './server/db.ts';
import {
  addDaysDateString,
  createNotification,
  ensureDeadlineNotifications,
  logActivity,
  todayDateString,
} from './server/notifications.ts';

const VALID_PRIORITIES = new Set(['High', 'Medium', 'Low']);
const VALID_STATUSES = new Set(['Pending', 'In Progress', 'Completed']);

interface TaskRow {
  id: string;
  title: string;
  description: string;
  user_id: string;
  assigned_to: string | null;
  project_id: string | null;
  priority: 'High' | 'Medium' | 'Low';
  status: 'Pending' | 'In Progress' | 'Completed';
  due_date: string | null;
  completed_at: string | null;
  created_at: string;
  updated_at: string;
  creator_name?: string;
  assignee_name?: string | null;
  project_name?: string | null;
}

function formatTask(row: TaskRow) {
  const today = todayDateString();
  const isOverdue = Boolean(
    row.due_date && row.due_date < today && row.status !== 'Completed'
  );
  return {
    ...row,
    is_overdue: isOverdue,
  };
}

function isProjectMemberOrOwner(projectId: string, userId: string): boolean {
  const project = db
    .prepare('SELECT owner_id FROM projects WHERE id = ?')
    .get(projectId) as { owner_id: string } | undefined;
  if (!project) return false;
  if (project.owner_id === userId) return true;
  const member = db
    .prepare('SELECT 1 FROM project_members WHERE project_id = ? AND user_id = ?')
    .get(projectId, userId);
  return Boolean(member);
}

function getTaskWithJoins(taskId: string): TaskRow | undefined {
  return db
    .prepare(
      `SELECT t.*,
              creator.name AS creator_name,
              assignee.name AS assignee_name,
              p.project_name AS project_name
       FROM tasks t
       JOIN users creator ON creator.id = t.user_id
       LEFT JOIN users assignee ON assignee.id = t.assigned_to
       LEFT JOIN projects p ON p.id = t.project_id
       WHERE t.id = ?`
    )
    .get(taskId) as TaskRow | undefined;
}

async function startServer() {
  const app = express();
  app.set('trust proxy', 1);
  app.disable('x-powered-by');

  app.use(express.json({ limit: '1mb' }));

  app.use((req, res, next) => {
    res.setHeader('X-Content-Type-Options', 'nosniff');
    res.setHeader('Referrer-Policy', 'strict-origin-when-cross-origin');

    const origin = req.headers.origin;
    const allowedAppUrl = process.env.APP_URL?.trim();
    const hostHeader = req.headers['x-forwarded-host'] || req.headers.host;

    if (origin) {
      let originAllowed = false;
      try {
        const originUrl = new URL(origin);
        if (hostHeader && originUrl.host === hostHeader) {
          originAllowed = true;
        } else if (allowedAppUrl && origin === allowedAppUrl) {
          originAllowed = true;
        }
      } catch {
        originAllowed = false;
      }

      if (originAllowed) {
        res.setHeader('Access-Control-Allow-Origin', origin);
        res.setHeader('Vary', 'Origin');
        res.setHeader('Access-Control-Allow-Methods', 'GET,POST,PUT,PATCH,DELETE,OPTIONS');
        res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
      }
    }

    if (req.method === 'OPTIONS') {
      res.status(204).end();
      return;
    }
    next();
  });

  const authRateLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: 30,
    standardHeaders: true,
    legacyHeaders: false,
    message: { status: 429, message: 'Too many authentication attempts. Please try again later.' },
  });

  // Bootstrap status for first-run admin setup
  app.get('/api/auth/bootstrap-status', (_req: Request, res: Response) => {
    const adminRow = db
      .prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'")
      .get() as { count: number };
    res.json({ adminClaimed: adminRow.count > 0 });
  });

  // Atomic one-time first-run admin bootstrap
  app.post('/api/auth/claim-admin', authRateLimiter, async (req: Request, res: Response) => {
    const { name, email, password } = req.body ?? {};

    if (!isNonEmptyString(name, 80)) {
      res.status(400).json({ status: 400, message: 'Name is required (max 80 characters).' });
      return;
    }
    if (!isValidEmail(email)) {
      res.status(400).json({ status: 400, message: 'Please provide a valid email address.' });
      return;
    }
    if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
      res.status(400).json({ status: 400, message: 'Password must be between 8 and 128 characters.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const passwordHash = await bcrypt.hash(password, 10);
    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();

    try {
      db.exec('BEGIN IMMEDIATE;');
      const adminRow = db
        .prepare("SELECT COUNT(*) AS count FROM users WHERE role = 'admin'")
        .get() as { count: number };

      if (adminRow.count > 0) {
        db.exec('ROLLBACK;');
        res.status(409).json({
          status: 409,
          message: 'Workspace administrator has already been claimed. Please sign in or register normally.',
        });
        return;
      }

      const existingEmail = db
        .prepare('SELECT id FROM users WHERE email = ?')
        .get(normalizedEmail);
      if (existingEmail) {
        db.exec('ROLLBACK;');
        res.status(409).json({ status: 409, message: 'An account with this email already exists.' });
        return;
      }

      db.prepare(
        `INSERT INTO users (id, name, email, password_hash, role, is_active, created_at)
         VALUES (?, ?, ?, ?, 'admin', 1, ?)`
      ).run(id, name.trim(), normalizedEmail, passwordHash, createdAt);
      db.exec('COMMIT;');

      const user = {
        id,
        name: name.trim(),
        email: normalizedEmail,
        role: 'admin' as const,
        is_active: 1,
        created_at: createdAt,
      };
      const token = signAccessToken(user);
      res.status(201).json({ token, user });
    } catch {
      try {
        db.exec('ROLLBACK;');
      } catch {
        // ignore rollback error
      }
      res.status(500).json({ status: 500, message: 'Unable to initialize administrator account.' });
    }
  });

  // Register user
  app.post('/api/register', authRateLimiter, async (req: Request, res: Response) => {
    const { name, email, password } = req.body ?? {};

    if (!isNonEmptyString(name, 80)) {
      res.status(400).json({ status: 400, message: 'Name is required (max 80 characters).' });
      return;
    }
    if (!isValidEmail(email)) {
      res.status(400).json({ status: 400, message: 'Please provide a valid email address.' });
      return;
    }
    if (typeof password !== 'string' || password.length < 8 || password.length > 128) {
      res.status(400).json({ status: 400, message: 'Password must be at least 8 characters.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const existing = db
      .prepare('SELECT id FROM users WHERE email = ?')
      .get(normalizedEmail);

    if (existing) {
      res.status(409).json({ status: 409, message: 'An account with this email already exists.' });
      return;
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const id = crypto.randomUUID();
    const createdAt = new Date().toISOString();

    db.prepare(
      `INSERT INTO users (id, name, email, password_hash, role, is_active, created_at)
       VALUES (?, ?, ?, ?, 'user', 1, ?)`
    ).run(id, name.trim(), normalizedEmail, passwordHash, createdAt);

    const user = {
      id,
      name: name.trim(),
      email: normalizedEmail,
      role: 'user' as const,
      is_active: 1,
      created_at: createdAt,
    };

    const token = signAccessToken(user);
    res.status(201).json({ token, user });
  });

  // Login user
  app.post('/api/login', authRateLimiter, async (req: Request, res: Response) => {
    const { email, password } = req.body ?? {};

    if (!isValidEmail(email) || typeof password !== 'string' || password.length === 0) {
      res.status(400).json({ status: 400, message: 'Email and password are required.' });
      return;
    }

    const normalizedEmail = email.trim().toLowerCase();
    const row = db
      .prepare(
        'SELECT id, name, email, password_hash, role, is_active, created_at FROM users WHERE email = ?'
      )
      .get(normalizedEmail) as
      | {
          id: string;
          name: string;
          email: string;
          password_hash: string;
          role: 'user' | 'admin';
          is_active: number;
          created_at: string;
        }
      | undefined;

    if (!row) {
      res.status(401).json({ status: 401, message: 'Invalid email or password.' });
      return;
    }

    const validPassword = await bcrypt.compare(password, row.password_hash);
    if (!validPassword) {
      res.status(401).json({ status: 401, message: 'Invalid email or password.' });
      return;
    }

    if (row.is_active !== 1) {
      res.status(403).json({
        status: 403,
        message: 'Your account has been deactivated by an administrator.',
      });
      return;
    }

    ensureDeadlineNotifications(row.id);

    const user = {
      id: row.id,
      name: row.name,
      email: row.email,
      role: row.role,
      is_active: row.is_active,
      created_at: row.created_at,
    };
    const token = signAccessToken(user);
    res.json({ token, user });
  });

  // Current user profile
  app.get('/api/me', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    res.json({ user: req.user });
  });

  app.put('/api/me', authenticateToken, async (req: AuthenticatedRequest, res: Response) => {
    const currentUser = req.user!;
    const { name, currentPassword, newPassword } = req.body ?? {};

    if (name !== undefined && !isNonEmptyString(name, 80)) {
      res.status(400).json({ status: 400, message: 'Name must be between 1 and 80 characters.' });
      return;
    }

    if (newPassword !== undefined && newPassword !== '') {
      if (typeof currentPassword !== 'string' || currentPassword.length === 0) {
        res.status(400).json({
          status: 400,
          message: 'Current password is required to set a new password.',
        });
        return;
      }
      if (typeof newPassword !== 'string' || newPassword.length < 8 || newPassword.length > 128) {
        res.status(400).json({
          status: 400,
          message: 'New password must be between 8 and 128 characters.',
        });
        return;
      }

      const row = db
        .prepare('SELECT password_hash FROM users WHERE id = ?')
        .get(currentUser.id) as { password_hash: string };

      const matches = await bcrypt.compare(currentPassword, row.password_hash);
      if (!matches) {
        res.status(401).json({ status: 401, message: 'Current password is incorrect.' });
        return;
      }

      const nextHash = await bcrypt.hash(newPassword, 10);
      db.prepare('UPDATE users SET password_hash = ? WHERE id = ?').run(nextHash, currentUser.id);
    }

    const updatedName = typeof name === 'string' ? name.trim() : currentUser.name;
    db.prepare('UPDATE users SET name = ? WHERE id = ?').run(updatedName, currentUser.id);

    const updatedUser = db
      .prepare('SELECT id, name, email, role, is_active, created_at FROM users WHERE id = ?')
      .get(currentUser.id);
    res.json({ user: updatedUser });
  });

  // Tasks endpoints
  app.get('/api/tasks', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    const userId = req.user!.id;
    const search = typeof req.query.search === 'string' ? req.query.search.trim() : '';
    const status = typeof req.query.status === 'string' ? req.query.status.trim() : '';
    const priority = typeof req.query.priority === 'string' ? req.query.priority.trim() : '';
    const projectId = typeof req.query.project_id === 'string' ? req.query.project_id.trim() : '';
    const overdue = req.query.overdue === 'true';
    const dueFrom = typeof req.query.due_from === 'string' ? req.query.due_from.trim() : '';
    const dueTo = typeof req.query.due_to === 'string' ? req.query.due_to.trim() : '';
    const sort = typeof req.query.sort === 'string' ? req.query.sort.trim() : 'created_at';
    const order = req.query.order === 'asc' ? 'ASC' : 'DESC';

    const whereClauses: string[] = [
      `(
        t.user_id = ?
        OR t.assigned_to = ?
        OR EXISTS (
          SELECT 1 FROM projects p2
          WHERE p2.id = t.project_id
            AND (
              p2.owner_id = ?
              OR EXISTS (
                SELECT 1 FROM project_members pm2
                WHERE pm2.project_id = p2.id AND pm2.user_id = ?
              )
            )
        )
      )`,
    ];
    const params: unknown[] = [userId, userId, userId, userId];

    if (search.length > 0) {
      whereClauses.push('LOWER(t.title) LIKE ?');
      params.push(`%${search.toLowerCase()}%`);
    }
    if (status && VALID_STATUSES.has(status)) {
      whereClauses.push('t.status = ?');
      params.push(status);
    }
    if (priority && VALID_PRIORITIES.has(priority)) {
      whereClauses.push('t.priority = ?');
      params.push(priority);
    }
    if (projectId === 'personal') {
      whereClauses.push('t.project_id IS NULL');
    } else if (projectId.length > 0) {
      whereClauses.push('t.project_id = ?');
      params.push(projectId);
    }
    if (overdue) {
      whereClauses.push("t.due_date IS NOT NULL AND t.due_date < ? AND t.status != 'Completed'");
      params.push(todayDateString());
    }
    if (dueFrom && isValidDateOnly(dueFrom)) {
      whereClauses.push('t.due_date >= ?');
      params.push(dueFrom);
    }
    if (dueTo && isValidDateOnly(dueTo)) {
      whereClauses.push('t.due_date <= ?');
      params.push(dueTo);
    }

    let orderBySql = `t.created_at ${order}`;
    if (sort === 'due_date') {
      orderBySql = `CASE WHEN t.due_date IS NULL THEN 1 ELSE 0 END, t.due_date ${order}, t.created_at DESC`;
    } else if (sort === 'priority') {
      orderBySql = `CASE t.priority WHEN 'High' THEN 1 WHEN 'Medium' THEN 2 ELSE 3 END ${order}, t.created_at DESC`;
    }

    const sql = `
      SELECT t.*,
             creator.name AS creator_name,
             assignee.name AS assignee_name,
             p.project_name AS project_name
      FROM tasks t
      JOIN users creator ON creator.id = t.user_id
      LEFT JOIN users assignee ON assignee.id = t.assigned_to
      LEFT JOIN projects p ON p.id = t.project_id
      WHERE ${whereClauses.join(' AND ')}
      ORDER BY ${orderBySql}
    `;

    const rows = db.prepare(sql).all(...params) as unknown as TaskRow[];
    res.json({ tasks: rows.map(formatTask) });
  });

  app.post('/api/tasks', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    const user = req.user!;
    const {
      title,
      description = '',
      priority = 'Medium',
      status = 'Pending',
      due_date = null,
      project_id = null,
      assigned_to = null,
    } = req.body ?? {};

    if (!isNonEmptyString(title, 200)) {
      res.status(400).json({ status: 400, message: 'Task title is required (max 200 characters).' });
      return;
    }
    if (typeof description !== 'string' || description.length > 2000) {
      res.status(400).json({ status: 400, message: 'Description must be under 2000 characters.' });
      return;
    }
    if (typeof priority !== 'string' || !VALID_PRIORITIES.has(priority)) {
      res.status(400).json({ status: 400, message: 'Priority must be High, Medium, or Low.' });
      return;
    }
    if (typeof status !== 'string' || !VALID_STATUSES.has(status)) {
      res.status(400).json({ status: 400, message: 'Status must be Pending, In Progress, or Completed.' });
      return;
    }

    const normalizedDueDate =
      due_date === null || due_date === '' ? null : isValidDateOnly(due_date) ? due_date : 'INVALID';
    if (normalizedDueDate === 'INVALID') {
      res.status(400).json({ status: 400, message: 'Due date must be a valid YYYY-MM-DD date.' });
      return;
    }

    let normalizedProjectId: string | null = null;
    if (typeof project_id === 'string' && project_id.trim().length > 0) {
      normalizedProjectId = project_id.trim();
      if (!isProjectMemberOrOwner(normalizedProjectId, user.id)) {
        res.status(403).json({
          status: 403,
          message: 'You do not have permission to add tasks to this project.',
        });
        return;
      }
    }

    let normalizedAssigneeId: string | null = null;
    if (typeof assigned_to === 'string' && assigned_to.trim().length > 0) {
      normalizedAssigneeId = assigned_to.trim();
      if (normalizedProjectId) {
        if (!isProjectMemberOrOwner(normalizedProjectId, normalizedAssigneeId)) {
          res.status(400).json({
            status: 400,
            message: 'Assignee must be a member of the selected project.',
          });
          return;
        }
      } else if (normalizedAssigneeId !== user.id) {
        res.status(400).json({
          status: 400,
          message: 'Personal tasks without a project can only be assigned to yourself.',
        });
        return;
      }
    } else {
      normalizedAssigneeId = user.id;
    }

    const id = crypto.randomUUID();
    const now = new Date().toISOString();
    const completedAt = status === 'Completed' ? now : null;

    db.prepare(
      `INSERT INTO tasks
       (id, title, description, user_id, assigned_to, project_id, priority, status, due_date, completed_at, created_at, updated_at)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
    ).run(
      id,
      title.trim(),
      description.trim(),
      user.id,
      normalizedAssigneeId,
      normalizedProjectId,
      priority,
      status,
      normalizedDueDate,
      completedAt,
      now,
      now
    );

    if (normalizedAssigneeId && normalizedAssigneeId !== user.id) {
      createNotification({
        userId: normalizedAssigneeId,
        type: 'assigned',
        taskId: id,
        message: `${user.name} assigned you to "${title.trim()}".`,
      });
    }

    logActivity({
      userId: user.id,
      actorName: user.name,
      action: 'created task',
      targetTitle: title.trim(),
      projectId: normalizedProjectId,
    });

    ensureDeadlineNotifications(user.id);
    if (normalizedAssigneeId && normalizedAssigneeId !== user.id) {
      ensureDeadlineNotifications(normalizedAssigneeId);
    }

    const created = getTaskWithJoins(id)!;
    res.status(201).json({ task: formatTask(created) });
  });

  app.put('/api/tasks/:id', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    const user = req.user!;
    const taskId = req.params.id;
    const existing = db.prepare('SELECT * FROM tasks WHERE id = ?').get(taskId) as TaskRow | undefined;

    if (!existing) {
      res.status(404).json({ status: 404, message: 'Task not found.' });
      return;
    }

    let isProjectOwner = false;
    if (existing.project_id) {
      const proj = db
        .prepare('SELECT owner_id FROM projects WHERE id = ?')
        .get(existing.project_id) as { owner_id: string } | undefined;
      isProjectOwner = proj?.owner_id === user.id;
    }

    const canEdit =
      existing.user_id === user.id || existing.assigned_to === user.id || isProjectOwner;
    if (!canEdit) {
      res.status(403).json({ status: 403, message: 'You do not have permission to edit this task.' });
      return;
    }

    const { title, description, priority, status, due_date, project_id, assigned_to } = req.body ?? {};

    const nextTitle = title !== undefined ? title : existing.title;
    if (!isNonEmptyString(nextTitle, 200)) {
      res.status(400).json({ status: 400, message: 'Task title is required (max 200 characters).' });
      return;
    }

    const nextDescription = description !== undefined ? description : existing.description;
    if (typeof nextDescription !== 'string' || nextDescription.length > 2000) {
      res.status(400).json({ status: 400, message: 'Description must be under 2000 characters.' });
      return;
    }

    const nextPriority = priority !== undefined ? priority : existing.priority;
    if (typeof nextPriority !== 'string' || !VALID_PRIORITIES.has(nextPriority)) {
      res.status(400).json({ status: 400, message: 'Invalid priority value.' });
      return;
    }

    const nextStatus = status !== undefined ? status : existing.status;
    if (typeof nextStatus !== 'string' || !VALID_STATUSES.has(nextStatus)) {
      res.status(400).json({ status: 400, message: 'Invalid status value.' });
      return;
    }

    let nextDueDate = existing.due_date;
    if (due_date !== undefined) {
      if (due_date === null || due_date === '') {
        nextDueDate = null;
      } else if (isValidDateOnly(due_date)) {
        nextDueDate = due_date;
      } else {
        res.status(400).json({ status: 400, message: 'Due date must be a valid YYYY-MM-DD date.' });
        return;
      }
    }

    let nextProjectId = existing.project_id;
    if (project_id !== undefined) {
      if (project_id === null || project_id === '') {
        nextProjectId = null;
      } else if (typeof project_id === 'string') {
        if (!isProjectMemberOrOwner(project_id, user.id)) {
          res.status(403).json({ status: 403, message: 'You do not belong to the selected project.' });
          return;
        }
        nextProjectId = project_id;
      }
    }

    let nextAssignee = existing.assigned_to;
    if (assigned_to !== undefined) {
      if (assigned_to === null || assigned_to === '') {
        nextAssignee = null;
      } else if (typeof assigned_to === 'string') {
        if (nextProjectId) {
          if (!isProjectMemberOrOwner(nextProjectId, assigned_to)) {
            res.status(400).json({
              status: 400,
              message: 'Assignee must be a member of the selected project.',
            });
            return;
          }
        } else if (assigned_to !== existing.user_id && assigned_to !== user.id) {
          res.status(400).json({
            status: 400,
            message: 'Personal tasks can only be assigned to the creator.',
          });
          return;
        }
        nextAssignee = assigned_to;
      }
    }

    const now = new Date().toISOString();
    let nextCompletedAt = existing.completed_at;
    if (nextStatus === 'Completed' && existing.status !== 'Completed') {
      nextCompletedAt = now;
    } else if (nextStatus !== 'Completed') {
      nextCompletedAt = null;
    }

    db.prepare(
      `UPDATE tasks
       SET title = ?, description = ?, priority = ?, status = ?, due_date = ?,
           project_id = ?, assigned_to = ?, completed_at = ?, updated_at = ?
       WHERE id = ?`
    ).run(
      nextTitle.trim(),
      nextDescription.trim(),
      nextPriority,
      nextStatus,
      nextDueDate,
      nextProjectId,
      nextAssignee,
      nextCompletedAt,
      now,
      taskId
    );

    if (nextAssignee && nextAssignee !== existing.assigned_to && nextAssignee !== user.id) {
      createNotification({
        userId: nextAssignee,
        type: 'assigned',
        taskId,
        message: `${user.name} assigned you to "${nextTitle.trim()}".`,
      });
    }

    if (nextStatus !== existing.status) {
      const notifyTargets = new Set<string>();
      if (existing.user_id !== user.id) notifyTargets.add(existing.user_id);
      if (nextAssignee && nextAssignee !== user.id) notifyTargets.add(nextAssignee);
      for (const targetUserId of notifyTargets) {
        createNotification({
          userId: targetUserId,
          type: 'status_changed',
          taskId,
          message: `${user.name} moved "${nextTitle.trim()}" to ${nextStatus}.`,
        });
      }

      logActivity({
        userId: user.id,
        actorName: user.name,
        action: nextStatus === 'Completed' ? 'completed task' : `marked task ${nextStatus}`,
        targetTitle: nextTitle.trim(),
        projectId: nextProjectId,
      });
    } else {
      logActivity({
        userId: user.id,
        actorName: user.name,
        action: 'updated task',
        targetTitle: nextTitle.trim(),
        projectId: nextProjectId,
      });
    }

    ensureDeadlineNotifications(user.id);

    const updated = getTaskWithJoins(taskId)!;
    res.json({ task: formatTask(updated) });
  });

  app.delete('/api/tasks/:id', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    const user = req.user!;
    const taskId = req.params.id;
    const existing = db.prepare('SELECT * FROM tasks WHERE id = ?').get(taskId) as TaskRow | undefined;

    if (!existing) {
      res.status(404).json({ status: 404, message: 'Task not found.' });
      return;
    }

    let isProjectOwner = false;
    if (existing.project_id) {
      const proj = db
        .prepare('SELECT owner_id FROM projects WHERE id = ?')
        .get(existing.project_id) as { owner_id: string } | undefined;
      isProjectOwner = proj?.owner_id === user.id;
    }

    if (existing.user_id !== user.id && !isProjectOwner) {
      res.status(403).json({ status: 403, message: 'Only the task creator or project owner can delete this task.' });
      return;
    }

    db.prepare('DELETE FROM tasks WHERE id = ?').run(taskId);
    logActivity({
      userId: user.id,
      actorName: user.name,
      action: 'deleted task',
      targetTitle: existing.title,
      projectId: existing.project_id,
    });

    res.json({ message: 'Task deleted successfully.' });
  });

  // Projects endpoints
  app.get('/api/projects', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    const userId = req.user!.id;
    const projects = db
      .prepare(
        `SELECT DISTINCT p.*, u.name AS owner_name, u.email AS owner_email
         FROM projects p
         JOIN users u ON u.id = p.owner_id
         LEFT JOIN project_members pm ON pm.project_id = p.id
         WHERE p.owner_id = ? OR pm.user_id = ?
         ORDER BY p.created_at DESC`
      )
      .all(userId, userId) as Array<{
      id: string;
      project_name: string;
      description: string;
      owner_id: string;
      owner_name: string;
      owner_email: string;
      created_at: string;
    }>;

    const membersStmt = db.prepare(
      `SELECT u.id, u.name, u.email, pm.added_at
       FROM project_members pm
       JOIN users u ON u.id = pm.user_id
       WHERE pm.project_id = ? AND u.is_active = 1
       ORDER BY u.name ASC`
    );

    const taskStatsStmt = db.prepare(
      `SELECT
         COUNT(*) AS total_tasks,
         SUM(CASE WHEN status = 'Completed' THEN 1 ELSE 0 END) AS completed_tasks
       FROM tasks
       WHERE project_id = ?`
    );

    const enriched = projects.map((p) => {
      const members = membersStmt.all(p.id) as Array<{
        id: string;
        name: string;
        email: string;
        added_at: string;
      }>;
      const stats = taskStatsStmt.get(p.id) as {
        total_tasks: number;
        completed_tasks: number | null;
      };
      return {
        ...p,
        members,
        total_tasks: stats.total_tasks ?? 0,
        completed_tasks: stats.completed_tasks ?? 0,
      };
    });

    res.json({ projects: enriched });
  });

  app.post('/api/projects', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    const user = req.user!;
    const { project_name, description = '' } = req.body ?? {};

    if (!isNonEmptyString(project_name, 120)) {
      res.status(400).json({ status: 400, message: 'Project name is required (max 120 characters).' });
      return;
    }
    if (typeof description !== 'string' || description.length > 1000) {
      res.status(400).json({ status: 400, message: 'Description must be under 1000 characters.' });
      return;
    }

    const id = crypto.randomUUID();
    const now = new Date().toISOString();

    db.prepare(
      `INSERT INTO projects (id, project_name, description, owner_id, created_at)
       VALUES (?, ?, ?, ?, ?)`
    ).run(id, project_name.trim(), description.trim(), user.id, now);

    db.prepare(
      `INSERT INTO project_members (project_id, user_id, added_at)
       VALUES (?, ?, ?)`
    ).run(id, user.id, now);

    logActivity({
      userId: user.id,
      actorName: user.name,
      action: 'created project',
      targetTitle: project_name.trim(),
      projectId: id,
    });

    res.status(201).json({
      project: {
        id,
        project_name: project_name.trim(),
        description: description.trim(),
        owner_id: user.id,
        owner_name: user.name,
        owner_email: user.email,
        created_at: now,
        members: [{ id: user.id, name: user.name, email: user.email, added_at: now }],
        total_tasks: 0,
        completed_tasks: 0,
      },
    });
  });

  app.put('/api/projects/:id', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    const user = req.user!;
    const projectId = req.params.id;
    const project = db
      .prepare('SELECT * FROM projects WHERE id = ?')
      .get(projectId) as { id: string; owner_id: string; project_name: string; description: string } | undefined;

    if (!project) {
      res.status(404).json({ status: 404, message: 'Project not found.' });
      return;
    }
    if (project.owner_id !== user.id) {
      res.status(403).json({ status: 403, message: 'Only the project owner can edit this project.' });
      return;
    }

    const { project_name, description } = req.body ?? {};
    const nextName = project_name !== undefined ? project_name : project.project_name;
    const nextDesc = description !== undefined ? description : project.description;

    if (!isNonEmptyString(nextName, 120)) {
      res.status(400).json({ status: 400, message: 'Project name is required (max 120 characters).' });
      return;
    }
    if (typeof nextDesc !== 'string' || nextDesc.length > 1000) {
      res.status(400).json({ status: 400, message: 'Description must be under 1000 characters.' });
      return;
    }

    db.prepare('UPDATE projects SET project_name = ?, description = ? WHERE id = ?').run(
      nextName.trim(),
      nextDesc.trim(),
      projectId
    );

    res.json({ message: 'Project updated.' });
  });

  app.delete('/api/projects/:id', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    const user = req.user!;
    const projectId = req.params.id;
    const project = db
      .prepare('SELECT id, owner_id, project_name FROM projects WHERE id = ?')
      .get(projectId) as { id: string; owner_id: string; project_name: string } | undefined;

    if (!project) {
      res.status(404).json({ status: 404, message: 'Project not found.' });
      return;
    }
    if (project.owner_id !== user.id) {
      res.status(403).json({ status: 403, message: 'Only the project owner can delete this project.' });
      return;
    }

    db.prepare('DELETE FROM projects WHERE id = ?').run(projectId);
    logActivity({
      userId: user.id,
      actorName: user.name,
      action: 'deleted project',
      targetTitle: project.project_name,
    });
    res.json({ message: 'Project deleted.' });
  });

  app.post('/api/projects/:id/members', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    const user = req.user!;
    const projectId = req.params.id;
    const { email } = req.body ?? {};

    if (!isValidEmail(email)) {
      res.status(400).json({ status: 400, message: 'Please enter a valid member email address.' });
      return;
    }

    const project = db
      .prepare('SELECT id, owner_id, project_name FROM projects WHERE id = ?')
      .get(projectId) as { id: string; owner_id: string; project_name: string } | undefined;

    if (!project) {
      res.status(404).json({ status: 404, message: 'Project not found.' });
      return;
    }
    if (project.owner_id !== user.id) {
      res.status(403).json({ status: 403, message: 'Only the project owner can add members.' });
      return;
    }

    const memberUser = db
      .prepare('SELECT id, name, email, is_active FROM users WHERE email = ?')
      .get(email.trim().toLowerCase()) as
      | { id: string; name: string; email: string; is_active: number }
      | undefined;

    if (!memberUser || memberUser.is_active !== 1) {
      res.status(404).json({
        status: 404,
        message: 'No active user found with that email. Ask them to register first.',
      });
      return;
    }

    const existingMember = db
      .prepare('SELECT 1 FROM project_members WHERE project_id = ? AND user_id = ?')
      .get(projectId, memberUser.id);
    if (existingMember) {
      res.status(409).json({ status: 409, message: 'User is already a member of this project.' });
      return;
    }

    const now = new Date().toISOString();
    db.prepare(
      'INSERT INTO project_members (project_id, user_id, added_at) VALUES (?, ?, ?)'
    ).run(projectId, memberUser.id, now);

    createNotification({
      userId: memberUser.id,
      type: 'assigned',
      message: `${user.name} added you to project "${project.project_name}".`,
    });

    logActivity({
      userId: user.id,
      actorName: user.name,
      action: `added ${memberUser.name} to project`,
      targetTitle: project.project_name,
      projectId,
    });

    res.status(201).json({
      member: {
        id: memberUser.id,
        name: memberUser.name,
        email: memberUser.email,
        added_at: now,
      },
    });
  });

  app.delete(
    '/api/projects/:id/members/:memberId',
    authenticateToken,
    (req: AuthenticatedRequest, res: Response) => {
      const user = req.user!;
      const { id: projectId, memberId } = req.params;

      const project = db
        .prepare('SELECT id, owner_id FROM projects WHERE id = ?')
        .get(projectId) as { id: string; owner_id: string } | undefined;

      if (!project) {
        res.status(404).json({ status: 404, message: 'Project not found.' });
        return;
      }
      if (project.owner_id !== user.id) {
        res.status(403).json({ status: 403, message: 'Only the project owner can remove members.' });
        return;
      }
      if (memberId === project.owner_id) {
        res.status(400).json({ status: 400, message: 'Cannot remove the project owner.' });
        return;
      }

      db.prepare('DELETE FROM project_members WHERE project_id = ? AND user_id = ?').run(
        projectId,
        memberId
      );
      db.prepare(
        'UPDATE tasks SET assigned_to = NULL WHERE project_id = ? AND assigned_to = ?'
      ).run(projectId, memberId);

      res.json({ message: 'Member removed from project.' });
    }
  );

  // Analytics & Dashboard summary
  app.get('/api/analytics', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    const userId = req.user!.id;
    ensureDeadlineNotifications(userId);

    const today = todayDateString();
    const next7Days = addDaysDateString(today, 7);

    const visibleTasks = db
      .prepare(
        `SELECT t.*,
                creator.name AS creator_name,
                assignee.name AS assignee_name,
                p.project_name AS project_name
         FROM tasks t
         JOIN users creator ON creator.id = t.user_id
         LEFT JOIN users assignee ON assignee.id = t.assigned_to
         LEFT JOIN projects p ON p.id = t.project_id
         WHERE t.user_id = ?
            OR t.assigned_to = ?
            OR EXISTS (
              SELECT 1 FROM projects p2
              WHERE p2.id = t.project_id
                AND (
                  p2.owner_id = ?
                  OR EXISTS (
                    SELECT 1 FROM project_members pm2
                    WHERE pm2.project_id = p2.id AND pm2.user_id = ?
                  )
                )
            )`
      )
      .all(userId, userId, userId, userId) as unknown as TaskRow[];

    const formatted = visibleTasks.map(formatTask);

    const counts = {
      total: formatted.length,
      pending: formatted.filter((t) => t.status === 'Pending').length,
      inProgress: formatted.filter((t) => t.status === 'In Progress').length,
      completed: formatted.filter((t) => t.status === 'Completed').length,
      overdue: formatted.filter((t) => t.is_overdue).length,
    };

    const byPriority = {
      High: formatted.filter((t) => t.priority === 'High').length,
      Medium: formatted.filter((t) => t.priority === 'Medium').length,
      Low: formatted.filter((t) => t.priority === 'Low').length,
    };

    const upcomingTasks = formatted
      .filter(
        (t) =>
          t.status !== 'Completed' &&
          t.due_date !== null &&
          t.due_date >= today &&
          t.due_date <= next7Days
      )
      .sort((a, b) => (a.due_date ?? '').localeCompare(b.due_date ?? ''))
      .slice(0, 8);

    // Weekly completed over last 8 weeks
    const weeklyCompleted: Array<{ label: string; count: number }> = [];
    const now = new Date();
    // Align to Monday of current week
    const dayOfWeek = (now.getUTCDay() + 6) % 7;
    const currentWeekStart = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth(), now.getUTCDate() - dayOfWeek)
    );

    for (let i = 7; i >= 0; i--) {
      const weekStart = new Date(currentWeekStart);
      weekStart.setUTCDate(currentWeekStart.getUTCDate() - i * 7);
      const weekEnd = new Date(weekStart);
      weekEnd.setUTCDate(weekStart.getUTCDate() + 7);

      const startIso = weekStart.toISOString();
      const endIso = weekEnd.toISOString();

      const count = formatted.filter(
        (t) =>
          t.status === 'Completed' &&
          t.completed_at &&
          t.completed_at >= startIso &&
          t.completed_at < endIso
      ).length;

      const label = weekStart.toLocaleDateString('en-US', {
        month: 'short',
        day: 'numeric',
        timeZone: 'UTC',
      });
      weeklyCompleted.push({ label, count });
    }

    const recentActivity = db
      .prepare(
        `SELECT a.*
         FROM activity_logs a
         WHERE a.user_id = ?
            OR (
              a.project_id IS NOT NULL
              AND EXISTS (
                SELECT 1 FROM projects p
                LEFT JOIN project_members pm ON pm.project_id = p.id
                WHERE p.id = a.project_id AND (p.owner_id = ? OR pm.user_id = ?)
              )
            )
         ORDER BY a.created_at DESC
         LIMIT 12`
      )
      .all(userId, userId, userId);

    res.json({
      counts,
      byStatus: {
        Pending: counts.pending,
        'In Progress': counts.inProgress,
        Completed: counts.completed,
      },
      byPriority,
      weeklyCompleted,
      upcomingTasks,
      recentActivity,
    });
  });

  // Notifications endpoints
  app.get('/api/notifications', authenticateToken, (req: AuthenticatedRequest, res: Response) => {
    const userId = req.user!.id;
    ensureDeadlineNotifications(userId);

    const notifications = db
      .prepare(
        `SELECT * FROM notifications
         WHERE user_id = ?
         ORDER BY created_at DESC
         LIMIT 50`
      )
      .all(userId) as Array<{ is_read: number }>;

    const unreadCount = notifications.filter((n) => n.is_read === 0).length;
    res.json({ notifications, unreadCount });
  });

  app.put(
    '/api/notifications/read-all',
    authenticateToken,
    (req: AuthenticatedRequest, res: Response) => {
      db.prepare('UPDATE notifications SET is_read = 1 WHERE user_id = ?').run(req.user!.id);
      res.json({ message: 'All notifications marked as read.' });
    }
  );

  app.put(
    '/api/notifications/:id/read',
    authenticateToken,
    (req: AuthenticatedRequest, res: Response) => {
      const result = db
        .prepare('UPDATE notifications SET is_read = 1 WHERE id = ? AND user_id = ?')
        .run(req.params.id, req.user!.id);
      if (result.changes === 0) {
        res.status(404).json({ status: 404, message: 'Notification not found.' });
        return;
      }
      res.json({ message: 'Notification marked as read.' });
    }
  );

  // Sample Workspace Seeder (opt-in from empty state)
  app.post(
    '/api/workspace/seed-sample',
    authenticateToken,
    (req: AuthenticatedRequest, res: Response) => {
      const user = req.user!;
      const existingCount = db
        .prepare('SELECT COUNT(*) AS count FROM tasks WHERE user_id = ?')
        .get(user.id) as { count: number };

      if (existingCount.count > 0) {
        res.status(409).json({
          status: 409,
          message: 'Workspace already contains tasks.',
        });
        return;
      }

      const now = new Date();
      const nowIso = now.toISOString();
      const today = todayDateString();

      const p1Id = crypto.randomUUID();
      const p2Id = crypto.randomUUID();

      db.prepare(
        'INSERT INTO projects (id, project_name, description, owner_id, created_at) VALUES (?, ?, ?, ?, ?)'
      ).run(
        p1Id,
        'Q4 Product Launch',
        'Core engineering, documentation, and release readiness tasks for V1 launch.',
        user.id,
        nowIso
      );
      db.prepare(
        'INSERT INTO project_members (project_id, user_id, added_at) VALUES (?, ?, ?)'
      ).run(p1Id, user.id, nowIso);

      db.prepare(
        'INSERT INTO projects (id, project_name, description, owner_id, created_at) VALUES (?, ?, ?, ?, ?)'
      ).run(
        p2Id,
        'Customer Onboarding',
        'Guides, account templates, and launch support workflows.',
        user.id,
        nowIso
      );
      db.prepare(
        'INSERT INTO project_members (project_id, user_id, added_at) VALUES (?, ?, ?)'
      ).run(p2Id, user.id, nowIso);

      const daysAgoIso = (days: number) => {
        const d = new Date(now);
        d.setUTCDate(d.getUTCDate() - days);
        return d.toISOString();
      };

      const sampleTasks = [
        {
          title: 'Finalize API authentication & rate-limit audit',
          description: 'Review JWT expiry, password hashing cost, and login rate limiting thresholds.',
          projectId: p1Id,
          priority: 'High',
          status: 'In Progress',
          dueDate: addDaysDateString(today, 1),
          completedAt: null,
        },
        {
          title: 'Prepare release notes and onboarding checklist',
          description: 'Summarize V1 features and quick-start steps for new workspaces.',
          projectId: p2Id,
          priority: 'Medium',
          status: 'Pending',
          dueDate: addDaysDateString(today, 3),
          completedAt: null,
        },
        {
          title: 'Verify mobile responsive layouts at 360px',
          description: 'Test sidebar drawer, Kanban board controls, and task modal on mobile viewports.',
          projectId: p1Id,
          priority: 'High',
          status: 'Pending',
          dueDate: today,
          completedAt: null,
        },
        {
          title: 'Update backup retention policy documentation',
          description: 'Confirm automated daily snapshot schedule and restore runbook.',
          projectId: p1Id,
          priority: 'Low',
          status: 'Pending',
          dueDate: addDaysDateString(today, -2),
          completedAt: null,
        },
        {
          title: 'Schedule team kickoff review for onboarding templates',
          description: 'Align on default project categories and priority definitions.',
          projectId: p2Id,
          priority: 'Medium',
          status: 'In Progress',
          dueDate: addDaysDateString(today, 5),
          completedAt: null,
        },
        {
          title: 'Configure database indexes for task queries',
          description: 'Index user_id, status, and due_date columns for fast filtering.',
          projectId: p1Id,
          priority: 'High',
          status: 'Completed',
          dueDate: addDaysDateString(today, -3),
          completedAt: daysAgoIso(2),
        },
        {
          title: 'Design weekly productivity chart layout',
          description: 'Add status breakdown and weekly completion trend charts.',
          projectId: p1Id,
          priority: 'Medium',
          status: 'Completed',
          dueDate: addDaysDateString(today, -9),
          completedAt: daysAgoIso(8),
        },
        {
          title: 'Draft welcome email copy for workspace invites',
          description: 'Keep instructions clear and concise for invited teammates.',
          projectId: p2Id,
          priority: 'Low',
          status: 'Completed',
          dueDate: addDaysDateString(today, -15),
          completedAt: daysAgoIso(14),
        },
        {
          title: 'Audit keyboard navigation and focus rings',
          description: 'Ensure forms and dialogs follow WCAG AA contrast and focus order.',
          projectId: null,
          priority: 'Medium',
          status: 'Completed',
          dueDate: addDaysDateString(today, -22),
          completedAt: daysAgoIso(21),
        },
      ];

      const insertTask = db.prepare(
        `INSERT INTO tasks
         (id, title, description, user_id, assigned_to, project_id, priority, status, due_date, completed_at, created_at, updated_at)
         VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`
      );

      for (const item of sampleTasks) {
        insertTask.run(
          crypto.randomUUID(),
          item.title,
          item.description,
          user.id,
          user.id,
          item.projectId,
          item.priority,
          item.status,
          item.dueDate,
          item.completedAt,
          nowIso,
          nowIso
        );
      }

      logActivity({
        userId: user.id,
        actorName: user.name,
        action: 'initialized sample workspace',
        targetTitle: 'Q4 Product Launch & Customer Onboarding',
        projectId: p1Id,
      });

      ensureDeadlineNotifications(user.id);
      res.status(201).json({ message: 'Sample projects and tasks loaded.' });
    }
  );

  // Admin Module endpoints
  app.get(
    '/api/admin/users',
    authenticateToken,
    requireAdmin,
    (req: AuthenticatedRequest, res: Response) => {
      const search = typeof req.query.search === 'string' ? req.query.search.trim().toLowerCase() : '';
      const rows = db
        .prepare(
          `SELECT u.id, u.name, u.email, u.role, u.is_active, u.created_at,
                  (SELECT COUNT(*) FROM tasks t WHERE t.user_id = u.id OR t.assigned_to = u.id) AS task_count,
                  (SELECT COUNT(*) FROM projects p WHERE p.owner_id = u.id) AS owned_projects
           FROM users u
           WHERE (? = '' OR LOWER(u.name) LIKE ? OR LOWER(u.email) LIKE ?)
           ORDER BY u.created_at DESC`
        )
        .all(search, `%${search}%`, `%${search}%`);

      res.json({ users: rows });
    }
  );

  app.patch(
    '/api/admin/users/:id',
    authenticateToken,
    requireAdmin,
    (req: AuthenticatedRequest, res: Response) => {
      const targetId = req.params.id;
      const { is_active, role } = req.body ?? {};

      const target = db
        .prepare('SELECT id, role, is_active FROM users WHERE id = ?')
        .get(targetId) as { id: string; role: 'user' | 'admin'; is_active: number } | undefined;

      if (!target) {
        res.status(404).json({ status: 404, message: 'User not found.' });
        return;
      }

      if (is_active !== undefined) {
        if (typeof is_active !== 'boolean' && is_active !== 0 && is_active !== 1) {
          res.status(400).json({ status: 400, message: 'Invalid is_active flag.' });
          return;
        }
        const nextActive = is_active === true || is_active === 1 ? 1 : 0;
        if (targetId === req.user!.id && nextActive === 0) {
          res.status(400).json({ status: 400, message: 'You cannot deactivate your own account.' });
          return;
        }
        db.prepare('UPDATE users SET is_active = ? WHERE id = ?').run(nextActive, targetId);
      }

      if (role !== undefined) {
        if (role !== 'user' && role !== 'admin') {
          res.status(400).json({ status: 400, message: 'Role must be user or admin.' });
          return;
        }
        if (targetId === req.user!.id && role !== 'admin') {
          res.status(400).json({ status: 400, message: 'You cannot remove your own admin role.' });
          return;
        }
        db.prepare('UPDATE users SET role = ? WHERE id = ?').run(role, targetId);
      }

      const updated = db
        .prepare('SELECT id, name, email, role, is_active, created_at FROM users WHERE id = ?')
        .get(targetId);
      res.json({ user: updated });
    }
  );

  app.get(
    '/api/admin/projects',
    authenticateToken,
    requireAdmin,
    (_req: AuthenticatedRequest, res: Response) => {
      const projects = db
        .prepare(
          `SELECT p.*, u.name AS owner_name, u.email AS owner_email,
                  (SELECT COUNT(*) FROM project_members pm WHERE pm.project_id = p.id) AS member_count,
                  (SELECT COUNT(*) FROM tasks t WHERE t.project_id = p.id) AS task_count
           FROM projects p
           JOIN users u ON u.id = p.owner_id
           ORDER BY p.created_at DESC`
        )
        .all();

      res.json({ projects });
    }
  );

  app.delete(
    '/api/admin/projects/:id',
    authenticateToken,
    requireAdmin,
    (req: AuthenticatedRequest, res: Response) => {
      const result = db.prepare('DELETE FROM projects WHERE id = ?').run(req.params.id);
      if (result.changes === 0) {
        res.status(404).json({ status: 404, message: 'Project not found.' });
        return;
      }
      res.json({ message: 'Project deleted by administrator.' });
    }
  );

  // API 404 fallback
  app.use('/api/*', (_req: Request, res: Response) => {
    res.status(404).json({ status: 404, message: 'API endpoint not found.' });
  });

  if (process.env.NODE_ENV !== 'production') {
    const { createServer: createViteServer } = await import('vite');
    const vite = await createViteServer({
      server: { middlewareMode: true },
      appType: 'spa',
    });
    app.use(vite.middlewares);
  } else {
    const distDir = path.resolve(process.cwd(), 'dist');
    app.use(express.static(distDir));
    app.get('*', (_req: Request, res: Response) => {
      const indexFile = path.join(distDir, 'index.html');
      if (fs.existsSync(indexFile)) {
        res.sendFile(indexFile);
      } else {
        res.status(404).send('Build output not found.');
      }
    });
  }

  const PORT = Number(process.env.PORT) || 3000;
  app.listen(PORT, '0.0.0.0', () => {
    console.log(`TaskFlow server listening on http://0.0.0.0:${PORT}`);
  });
}

startServer().catch((err) => {
  console.error('Failed to start TaskFlow server:', err);
  process.exit(1);
});
