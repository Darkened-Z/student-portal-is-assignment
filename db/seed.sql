-- Seed data for Student Portal
-- Passwords stored as plain text (vulnerable version) or bcrypt hash (note: seeded plain for demo)

INSERT OR IGNORE INTO users (username, password, email, role) VALUES
    ('admin',   'admin123',    'admin@portal.edu',   'admin'),
    ('tayyaba', 'pass@123',    'tayyaba@portal.edu', 'student'),
    ('zeeshan', 'zeeshan99',   'zeeshan@portal.edu', 'student'),
    ('sara',    'sara2024',    'sara@portal.edu',    'student');

INSERT OR IGNORE INTO courses (name, category, instructor, description) VALUES
    ('Information Security',    'CS',   'Dr. Imran', 'Covers network security, cryptography, and ethical hacking.'),
    ('Data Structures',         'CS',   'Dr. Ayesha','Trees, graphs, heaps and algorithm complexity.'),
    ('Operating Systems',       'CS',   'Dr. Bilal', 'Process management, memory, file systems.'),
    ('Database Systems',        'CS',   'Dr. Nadia', 'ER diagrams, normalization, SQL queries.'),
    ('Computer Networks',       'CS',   'Dr. Tariq', 'OSI model, TCP/IP, routing and switching.');

INSERT OR IGNORE INTO enrollments (user_id, course_id) VALUES
    (2, 1), (2, 2), (2, 4),
    (3, 1), (3, 3),
    (4, 2), (4, 5);

INSERT OR IGNORE INTO comments (user_id, course_id, content) VALUES
    (2, 1, 'Great course! Learned a lot about buffer overflows.'),
    (3, 1, 'The lab sessions are very hands-on.'),
    (4, 2, 'Data structures is challenging but worth it.');
